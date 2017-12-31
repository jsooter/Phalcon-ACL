<?php

use \Phalcon\Events\Event;
use \Phalcon\Mvc\Dispatcher;
/*
Acl
====
This class applies access control based on a combination of module, controller
and view. Permissions are provided by the Permission model and compaired against
a user's list of permissions that are stored in the session. This class also
contains related static functions.
*/
class Acl extends \Phalcon\Mvc\User\Component
{
    /*
    $_module : string
    The current module
    */
    protected $_module;
    protected $_controller;
    protected $_action;
    protected $dispatcher;
    protected $exempt_modules;
    /*
    __construct($module)
    ====
    Create and instance, set $this->_module

    Parameters
    ----
    $module : string the current module
    */
    public function __construct($module)
    {
        $this->_module = $module;
        $this->exempt_modules = ['frontend','backend']; //do not require login
    }
    public function checkPostCsrf(){
        if ($this->request->isPost() == true) {
            try{
                // Run CSRF check, on POST data, in exception mode, Does not expire, and is reusable.
                // requires NoCSRF library: http://bkcore.com/blog/code/nocsrf-php-class.html
                $noCsrf = \NoCSRF::check( 'csrf_token', $_POST, true, null, true );
            } catch ( Exception $e ) {
                // notify that there is a CSRF vulnerability here
            }
            // login route is exempt
            if(!$noCsrf && $this->_module != 'backend' && $this->_controller != 'session' && $this->_action != 'start'){
                $response = array(
                    'status' => 'danger',
                    'message' => 'ACCESS DENIED NO CSRF'
                );
                \Helpers\Controller::jsonify($response);
                die();
                // send CSRF atempt notification to admin
            }
            // cleanup POST
            unset($_POST['csrf_token']);
        }
    }
    /*
    setSessionTimestamp()
    ====
    Handy for updating a timestamp value in the session to prevenfrom expiring
    */
    public function setSessionTimestamp(){
        $auth = $this->session->get('auth');
        if(!empty($auth)){
            $auth['last_active'] = date("c");
            $this->session->set('auth', $auth);
            return $auth['last_active'];
        }
        return false;
    }
    /*
    beforeExecuteRoute()
    ====
    Intercept the dispatcher, apply access rules, and pass data to the view

    Parameters
    ----
    $event
    $dispatcher : object
    */
    public function beforeExecuteRoute(Event $event, Dispatcher $dispatcher) {
        //Take the active controller/action from the dispatcher
        $this->dispatcher = $dispatcher;
        $this->_controller = $this->dispatcher->getControllerName();
        $this->_action = $this->dispatcher->getActionName();

        //get user
        $auth = $this->session->get('auth');
        $user = \Multiple\Models\User::findFirst(array(
            "username = :username:",
            "bind" => array(
                "username" => $auth['username']
            )
        ));
        if($user) {
            // set user loggin status to true for base level access
            $this->view->user_logged_in = true;
            // pass variables to view
            $this->view->setVar('user',$user);
            $this->view->setVar('permissions', \Acl::permissions($auth['username']));
            $this->view->setVar('session_expires',$this->session->get('expires_on'));
            $csrf_token = $this->session->get('csrf_token');
            $this->view->setVar('csrf_token',$csrf_token);
            $this->view->isDevServer = Acl::isDevServer();
            $this->view->isDev = Acl::isDev();
            // write new data to the session to keep it from expiring
            $this->setSessionTimestamp();
            // check against user permissions (proceed if constraint doesn't exist)
            $isAllowed = Acl::isAllowed($user->permissions,$this->_module,$this->_controller,$this->_action);
            if($isAllowed === false){
                // if request is AJAX respond with JSON
                if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
                    $response = array(
                        'status' => 'danger',
                        'message' => 'ACCESS DENIED'
                    );
                    \Helpers\Controller::jsonify($response);
                    die();
                }
                // if request is a file upload
                if(!empty($_FILES)){
                    $response = array(
                        'status' => 'danger',
                        'message' => '<i class="uk-icon-exclamation-triangle"></i> ACCESS DENIED'
                    );
                    \Helpers\Controller::unauthorized($response);
                    die();
                }
                // all other requests
                $this->response->redirect('access-denied');
            }
        } else {
            $this->view->user_logged_in = false;
            // block all access if not logged in except for frontend module (public pages)
            if(!in_array($this->_module,$this->exempt_modules)){
                // allow login through backend module/ session controller
                if($this->_controller != 'session' && $this->_action == 'index'){
                    $this->cookies->set('pre_login_url', $this->router->getRewriteUri(), time() + 15 * 86400);
                    $cookie_expire = time() + (60 * 60);
                    $target_uri = $_SERVER['REQUEST_URI'];
                    setcookie("target_uri",$target_uri,$cookie_expire,'/');
                    $system_modules = ['manager', 'register'];
                    if(in_array($this->_module,$system_modules)){
                        $this->response->redirect('/system-login#', false, 401);
                    } else {
                        $this->response->redirect('/customer-login#', false, 401);
                    }
                }
            }
        }
        // CSRF prevention
        $this->checkPostCsrf();
    }
    /*
    isAllowed($permissions,$module,$controller,$action)
    ====
    Get permission ID for the module, controller, action combination and check
    it against the users permissions list stored in the session.

    Parameters
    ----
    $permissions : array
    $module : string
    $controller : string
    $action : string

    Returns
    ----
    bool _[returns true if the permission ID exists and is found in the user's
        permissions list, false if the ID is not in the list, and true if the
        permission ID does not exist.]_
    */
    public static function isAllowed($permissions,$module,$controller,$action){
        if(!$module || !$controller || !$action) return false;
        // get permissions for this module, controller, action
        $permission = \Multiple\Models\Permission::findFirst(array(
            "module = :module: AND controller = :controller: AND action = :action:",
            "bind" => array(
                "module"     => $module,
                "controller" => $controller,
                "action"     => $action
            )
        ));
        // check against user permissions (proceed if constraint doesn't exist)
        if($permission){
            // if permission is not in user's permission list
            if(!in_array($permission->id, $permissions)){
                return false;
            }
        }
        // if there is no permission then the route is not protected and access is allowed
        return true;
    }
    /*
    isDev()
    ====
    Check the session for dev flag. Returns true if dev otherwise false.

    Parameters
    ----
    $session
    */
    public static function isDev(){
        $session = Phalcon\DI::getDefault()->getSession();
        $auth = $session->get('auth');

        if($auth['username'] == "admin"){
            return true;
        }

        return false;
    }

    public static function isDevServer(){
        return ($_SERVER['SERVER_NAME'] != 'localhost');
    }
    /*
    permissions()
    ====
    Returns a list of permissions for given username. This list can be checked in the view.

    Parameters
    ----
    $username : string
    */
    public static function permissions($username){
        if(!$username) return false;
        $user = \Multiple\Models\User::findFirst(array(
            "username = :username:",
            "bind" => array(
                "username" => $username
            )
        ));
        if(!$user) return false;
        $permissions = \Multiple\Models\Permission::find();
        $permission_list = array();
        foreach($permissions as $row){
            if(in_array($row->id,$user->permissions)){
                $permission_list[$row->name] = 1;
            } else {
                $permission_list[$row->name] = 0;
            }
        }
        return $permission_list;
    }
}