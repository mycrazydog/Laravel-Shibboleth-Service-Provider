<?php namespace StudentAffairsUwm\Shibboleth\Providers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider as UserProviderInterface;
use Illuminate\Hashing\BcryptHasher;

class ShibbolethUserProvider implements UserProviderInterface
{
    /**
     * The hasher implementation.
     *
     * @var \Illuminate\Hashing\BcryptHasher
     */
    protected $hasher;

    /**
     * The user model.
     *
     * @var string
     */
    protected $model;

    /**
     * Create a new Shibboleth user provider.
     *
     * @param  \Illuminate\Hashing\BcryptHasher  $hasher
     * @param  string  $model
     * @return void
     */
    public function __construct(BcryptHasher $hasher, $model)
    {
        $this->model  = $model;
        $this->hasher = $hasher;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed $identifier
     * @return \Illuminate\Auth\Authenticatable | null
     */
    public function retrieveById($identifier)
    {
        $user = $this->retrieveByCredentials(['id' => $identifier]);
        return ($user && $user->getAuthIdentifier() == $identifier) ? $user : null;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     * @return Illuminate\Auth\Authenticatable | null
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (count($credentials) == 0) {
            return null;
        }

        $class = '\\' . ltrim($this->model, '\\');
        $user  = new $class;

        $query = $user->newQuery();
        foreach ($credentials as $key => $value) {
            if (!str_contains($key, 'password')) {
                $query->where($key, $value);
            }

        }

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Auth\Authenticatable $user
     * @param  array $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return ($credentials['type'] === 'shibboleth') 
            ? true : $this->hasher->check($credentials['password'], $user->getAuthPassword());
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        // Not Implemented
    }

    /**
     * Retrieve a user by by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Auth\Authenticatable | null
     */
    public function retrieveByToken($identifier, $token)
    {
        // Not Implemented
    }
}
