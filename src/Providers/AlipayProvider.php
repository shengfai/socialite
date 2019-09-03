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
        
        return $this->getPublicFields($token, $parameters);
    }

    /**
     *
     * @param AccessTokenInterface $token
     */
    protected function getUserInfoFields(AccessTokenInterface $token)
    {
        $parameters = [
            'method' => 'alipay.system.oauth.token',
            'auth_token' => $token->getToken()
        ];
        
        return $this->getPublicFields($token, $parameters);
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
        $response = $this->getHttpClient()->get($this->getTokenUrl(), $this->getTokenFields($code));
        
        return $this->parseAccessToken($response->getBody()->getContents());
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
        $response = $this->getHttpClient()->get($this->getUserInfoUrl(), $this->getUserInfoFields($token));
        
        return $this->parseAccessToken($response->getBody()->getContents());
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
            'id' => $this->arrayItem($user, 'user_id'),
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
     *
     * @param
     *        $params
     *
     * @return string
     */
    protected function generateSign($params)
    {
        ksort($params);
        
        $stringToBeSigned = $this->clientSecret;
        
        foreach ($params as $k => $v) {
            if (!is_array($v) && '@' != substr($v, 0, 1)) {
                $stringToBeSigned .= "$k$v";
            }
        }
        
        $stringToBeSigned .= $this->clientSecret;
        
        return strtoupper(md5($stringToBeSigned));
    }
}
