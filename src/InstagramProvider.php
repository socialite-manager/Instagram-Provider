<?php

namespace Socialite\Provider;

use Socialite\Two\AbstractProvider;
use Socialite\Two\User;

class InstagramProvider extends AbstractProvider
{
    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['basic'];

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl(string $state)
    {
        return $this->buildAuthUrlFromBase(
            'https://api.instagram.com/oauth/authorize',
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://api.instagram.com/oauth/access_token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken(string $token)
    {
        $endpoint = '/users/self';
        $query = [
            'access_token' => $token,
        ];
        $signature = $this->generateSignature($endpoint, $query);
        $query['sig'] = $signature;
        $response = $this->getHttpClient()->get(
            'https://api.instagram.com/v1/users/self',
            [
            'query' => $query,
            'headers' => [
                'Accept' => 'application/json',
            ],
            ]
        );

        return json_decode($response->getBody()->getContents(), true)['data'];
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['id'],
            'nickname' => $user['username'],
            'name' => $user['full_name'],
            'email' => null,
            'avatar' => $user['profile_picture'],
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields(string $code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }

    /**
     * Allows compatibility for signed API requests.
     *
     * @param string $endpoint
     * @param array $params
     * @return string
     */
    protected function generateSignature(string $endpoint, array $params)
    {
        $sig = $endpoint;
        ksort($params);
        foreach ($params as $key => $val) {
            $sig .= "|$key=$val";
        }
        $signing_key = $this->clientSecret;
        return hash_hmac('sha256', $sig, $signing_key, false);
    }
}
