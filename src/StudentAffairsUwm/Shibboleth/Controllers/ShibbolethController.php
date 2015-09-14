<?php
namespace StudentAffairsUwm\Shibboleth\Controllers;

use Illuminate\Auth\GenericUser;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\View;
use JWTAuth;

class ShibbolethController extends Controller
{
    // TODO: Can we get rid of this and get it more dynamically?
    private $ctrpath = "\StudentAffairsUwm\\Shibboleth\\Controllers\\ShibbolethController@";

    /**
     * Service Provider
     * @var Shibalike\SP
     */
    private $sp;

    /**
     * Identity Provider
     * @var Shibalike\IdP
     */
    private $idp;

    /**
     * Configuration
     * @var Shibalike\Config
     */
    private $config;

    /**
     * Constructor
     */
    public function __construct(GenericUser $user = null)
    {
        $this->user = $user;
    }

    /**
     * Create the session, send the user away to the IDP
     * for authentication.
     */
    public function create()
    {
            return Redirect::to('https://' . Request::server('SERVER_NAME') . ':' . Request::server('SERVER_PORT') . config('shibboleth.idp_login') . '?target=' . action($this->ctrpath . "idpAuthorize"));
    }

    /**
     * Login for users not using the IdP.
     */
    public function localCreate()
    {
        return $this->viewOrRedirect(config('shibboleth.local_login'));
    }

    /**
     * Authorize function for users not using the IdP.
     */
    public function localAuthorize()
    {
        // TODO: Update this with the JWT stuff
        $email    = Input::get(config('shibboleth.local_login_user_field'));
        $password = Input::get(config('shibboleth.local_login_pass_field'));

        if (Auth::attempt(array('email' => $email, 'password' => $password), true)) {
            $userClass  = config('auth.model');
            $groupClass = config('auth.group_model');

            $user = $userClass::where('email', '=', $email)->first();
            if (isset($user->first_name)) {
                Session::put('first', $user->first_name);
            }

            if (isset($user->last_name)) {
                Session::put('last', $user->last_name);
            }

            if (isset($email)) {
                Session::put('email', $user->email);
            }

            if (isset($email)) {
                Session::put('id', User::where('email', '=', $email)->first()->id);
            }
            //TODO: Look at this

            //Group Session Field
            if (isset($email)) {
                try {
                    $group = $groupClass::whereHas('users', function ($q) {
                        $q->where('email', '=', Request::server(config('shibboleth.idp_login_email')));
                    })->first();

                    Session::put('group', $group->name);
                } catch (Exception $e) {
                    // TODO: Remove later after all auth is set up.
                    Session::put('group', 'undefined');
                }
            }

            // Set session to know user is local
            Session::put('auth_type', 'local');
            return $this->viewOrRedirect(config('shibboleth.local_authorized'));
        } else {
            return $this->viewOrRedirect(config('shibboleth.local_unauthorized'));
        }
    }

    /**
     * Setup authorization based on returned server variables
     * from the IdP.
     */
    public function idpAuthorize()
    {
        $email      = $this->getServerVariable(config('shibboleth.idp_login_email'));
        $first_name = $this->getServerVariable(config('shibboleth.idp_login_first'));
        $last_name  = $this->getServerVariable(config('shibboleth.idp_login_last'));

        $userClass  = config('auth.model');
        $groupClass = config('auth.group_model');

        // Attempt to login with the email, if success, update the user model
        // with data from the Shibboleth headers (if present)
        // TODO: This can be simplified a lot
        if (Auth::attempt(array('email' => $email, 'type' => 'shibboleth'), true)) {
            $user = $userClass::where('email', '=', $email)->first();

            // Update the modal as necessary
            if (isset($first_name)) {
                $user->first_name = $first_name;
            }

            if (isset($last_name)) {
                $user->last_name = $last_name;
            }

            $user->save();

            // This is where we used to setup a session. Now we will setup a token.
            $customClaims = ['auth_type' => 'idp'];
            $token        = JWTAuth::fromUser($user, $customClaims);

            // We need to pass the token... how?
            // Let's try this.
            return $this->viewOrRedirect(config('shibboleth.shibboleth_authenticated') . '?token=' . $token);

        } else {
            //Add user to group and send through auth.
            if (isset($email)) {
                if (config('shibboleth.add_new_users', true)) {
                    $user = $userClass::create(array(
                        'email'      => $email,
                        'type'       => 'shibboleth',
                        'first_name' => $first_name,
                        'last_name'  => $last_name,
                        'enabled'    => 0,
                    ));

                    try {
                        $group = $groupClass::findOrFail(config('shibboleth.shibboleth_group'));
                    } catch (\Illuminate\Database\Eloquent\ModelNotFoundException $e) {
                        $msg = "Could not find " . $groupClass . " with primary key " . config('shibboleth.shibboleth_group') . "! Check your Laravel-Shibboleth configuration.";
                        throw new \RuntimeException($msg, 900, $e);
                    }

                    $group->users()->save($user);
                    
                    return Redirect::to('https://' . Request::server('SERVER_NAME') . ':' . Request::server('SERVER_PORT') . config('shibboleth.idp_login') . '?target=' . action($this->ctrpath . "idpAuthorize"));
                    
                } else {
                    // Identify that the user was not in our database and will not be created (despite passing IdP)
                    Session::put('auth_type', 'no_user');
                    Session::put('group', 'undefined');

                    return $this->viewOrRedirect(config('shibboleth.shibboleth_unauthorized'));
                }
            }

            return $this->viewOrRedirect(config('shibboleth.login_fail'));
        }
    }

    /**
     * Destroy the current session and log the user out, redirect them to the main route.
     */
    public function destroy()
    {
        // TODO: Should get the user from token here
        Auth::logout();
        Session::flush();

        $token = JWTAuth::invalidate($_GET['token']);

        if (Session::get('auth_type') == 'idp') {
                return Redirect::to('https://' . Request::server('SERVER_NAME') . config('shibboleth.idp_logout'));
        } else {
            return $this->viewOrRedirect(config('shibboleth.local_logout'));
        }
    }

    /**
     * Function to get an attribute store for Shibalike
     */
    private function getAttrStore()
    {
        return new \Shibalike\Attr\Store\ArrayStore(config('shibboleth.emulate_idp_users'));
    }

    /**
     * Gets a state manager for Shibalike
     */
    private function getStateManager()
    {
        $session = \UserlandSession\SessionBuilder::instance()
            ->setSavePath(sys_get_temp_dir())
            ->setName('SHIBALIKE_BASIC')
            ->build();
        return new \Shibalike\StateManager\UserlandSession($session);
    }

    /**
     * Wrapper function for getting server variables.
     * Since Shibalike injects $_SERVER variables Laravel
     * doesn't pick them up. So depending on if we are
     * using the emulated IdP or a real one, we use the
     * appropriate function.
     */
    private function getServerVariable($variableName)
    {
        if (config('shibboleth.emulate_idp') == true) {
            return isset($_SERVER[$variableName]) ? $_SERVER[$variableName] : null;
        } else {
            $nonRedirect = Request::server($variableName);
            $redirect    = Request::server('REDIRECT_' . $variableName);
            return (!empty($nonRedirect)) ? $nonRedirect : $redirect;
        }
    }

    /*
     * Simple function that allows configuration variables
     * to be either names of views, or redirect routes.
     */
    private function viewOrRedirect($view)
    {
        return (View::exists($view)) ? view($view) : Redirect::to($view);
    }
}
