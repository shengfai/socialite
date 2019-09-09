<?php

/*
 * This file is part of the overtrue/socialite.
 * (c) overtrue <i@overtrue.me>
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Overtrue\Socialite\Providers;

use Overtrue\Socialite\AccessTokenInterface;
use Overtrue\Socialite\ProviderInterface;
use Overtrue\Socialite\User;
use Illuminate\Support\Str;
use Overtrue\Socialite\InvalidStateException;

/**
 *
 * Class AlipayProvider
 *
 * @author CocaCoffee <CocaCoffee@vip.qq.com>
 * @see https://docs.open.alipay.com/218/105329/
 */
class AlipayProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * The base url of Alipay API.
     *
     * @var string
     */
    protected $baseUrl = 'https://openapi.alipay.com/gateway.do';
    
    /**
     *
     * {@inheritdoc} .
     */
    protected $userId;
    
    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = [
        'authorization_code'
    ];
    
    /**
     * The API version for the request.
     *
     * @var string
     */
    protected $version = '1.0';
    
    /**
     *
     * @var string
     */
    protected $format = 'JSON';
    
    /**
     *
     * @var string
     */
    protected $signType = 'RSA2';

    /**
     * Get the authentication URL for the provider.
     *
     * @param string $state
     *
     * @return string
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->baseUrl, $state);
    }

    /**
     * Get the token URL for the provider.
     *
     * @return string
     */
    protected function getTokenUrl()
    {
        return $this->baseUrl;
    }

    /**
     * Get the user info URL for the provider.
     *
     * @return string
     */
    protected function getUserInfoUrl()
    {
        return $this->baseUrl;
    }

    /**
     *
     * @param array $parameters
     * @return array
     */
    protected function getPublicFields(array $parameters = [])
    {
        $fields = [
            'app_id' => $this->clientId,
            'format' => $this->format,
            'charset' => 'utf-8',
            'sign_type' => $this->signType,
            'timestamp' => date('Y-m-d H:i:s'),
            'version' => $this->version
        ];
        
        $fields = array_merge($parameters, $fields);
        $fields['sign'] = $this->generateSign($fields);
        
        return $fields;
    }

    /**
     * Get the Post fields for the token request.
     *
     * @param string $code
     *
     * @return array
     */
    protected function getTokenFields($code)
    {
        $parameters = [
            'method' => 'alipay.system.oauth.token',
            'code' => $code,
            'grant_type' => $this->formatScopes($this->scopes, $this->scopeSeparator)
        ];
        
        return $this->getPublicFields($parameters);
    }

    /**
     *
     * @param AccessTokenInterface $token
     */
    protected function getUserInfoFields(AccessTokenInterface $token)
    {
        $parameters = [
            'method' => 'alipay.user.info.share',
            'auth_token' => $token->getToken()
        ];
        
        return $this->getPublicFields($parameters);
    }

    /**
     * Get the access token for the given code.
     *
     * @param string $code
     *
     * @return \Overtrue\Socialite\AccessToken
     */
    public function getAccessToken($code)
    {
        try {
            
            $response = $this->getHttpClient()->get($this->getTokenUrl(), [
                'query' => $this->getTokenFields($code)
            ]);
            
            $result = json_decode($response->getBody()->getContents(), true);
            
            return $this->parseAccessToken($result['alipay_system_oauth_token_response']);
        
        } catch (\Exception $e) {
            throw new InvalidStateException($result['error_response']['sub_msg'], $result['error_response']['code']);
        }
    }

    /**
     * Get the raw user for the given access token.
     *
     * @param \Overtrue\Socialite\AccessTokenInterface $token
     *
     * @return array
     */
    protected function getUserByToken(AccessTokenInterface $token)
    {
        try {
            
            $response = $this->getHttpClient()->get($this->getUserInfoUrl(), [
                'query' => $this->getUserInfoFields($token)
            ]);
            
            $result = json_decode($response->getBody()->getContents(), true);
            
            return $result['alipay_user_info_share_response'];
        
        } catch (\Exception $e) {
            throw new InvalidStateException($result['error_response']['sub_msg'], $result['error_response']['code']);
        }
    }

    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param array $user
     *
     * @return \Overtrue\Socialite\User
     */
    protected function mapUserToObject(array $user)
    {
        return new User([
            'user_id' => $this->arrayItem($user, 'user_id'),
            'nickname' => $this->arrayItem($user, 'nick_name'),
            'name' => $this->arrayItem($user, 'nick_name'),
            'avatar' => $this->arrayItem($user, 'avatar'),
            'province' => $this->arrayItem($user, 'province'),
            'city' => $this->arrayItem($user, 'city'),
            'is_student_certified' => $this->arrayItem($user, 'is_student_certified'),
            'user_status' => $this->arrayItem($user, 'user_status'),
            'is_certified' => $this->arrayItem($user, 'is_certified'),
            'gender' => $this->arrayItem($user, 'gender')
        ]);
    }

    /**
     * Generate the sign for given params.
     *
     * @param array $params
     * @return string
     */
    protected function generateSign(array $params)
    {
        if (Str::endsWith($this->clientSecret, '.pem')) {
            $privateKey = openssl_pkey_get_private($this->clientSecret);
        } else {
            $privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" . wordwrap($this->clientSecret, 64, "\n", true) . "\n-----END RSA PRIVATE KEY-----";
        }
        
        $payload = $this->getSignContent($params);
        
        openssl_sign($payload, $sign, $privateKey, OPENSSL_ALGO_SHA256);
        
        $sign = base64_encode($sign);
        
        if (is_resource($privateKey)) {
            openssl_free_key($privateKey);
        }
        
        return $sign;
    }

    /**
     * Get the sign content for the given data.
     *
     * @param array $data
     * @param string $verify
     */
    protected function getSignContent(array $data, $verify = false): string
    {
        ksort($data);
        
        $stringToBeSigned = '';
        foreach ($data as $k => $v) {
            if ($verify && $k != 'sign' && $k != 'sign_type') {
                $stringToBeSigned .= $k . '=' . $v . '&';
            }
            if (!$verify && $v !== '' && !is_null($v) && $k != 'sign' && '@' != substr($v, 0, 1)) {
                $stringToBeSigned .= $k . '=' . $v . '&';
            }
        }
        
        return trim($stringToBeSigned, '&');
    }
}
