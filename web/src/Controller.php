<?php
use \Psr\Container\ContainerInterface;

class Controller
{

    private $_ci = null;

    /**
     * @var array
     */
    protected $_templateVars = [];

    /**
     * @var null
     */
    protected $_template = null;

    /**
     * @var \Psr\Http\Message\ServerRequestInterface
     */
    protected $_request = null;

    /**
     * @var \Psr\Http\Message\ResponseInterface
     */
    protected $_response = null;

    /**
     * @var mixed|null
     */
    protected $_view = null;

    /**
     * @var Profiles
     */
    protected $_profiles = null;

    protected $_config = null;

    public function __construct(ContainerInterface $ci)
    {
        $this->_ci = $ci;
        $this->_request = $ci->get('request');
        $this->_response = $ci->get('response');
        $this->_view = $ci->get('view');
        $this->_profiles = $ci->get('profiles');
    }

    public function set($vars)
    {
        $this->_templateVars = array_merge($this->_templateVars, $vars);
    }

    public function templateVars()
    {
        return $this->_templateVars;
    }

    public function render($template = '', $temp_var = [])
    {
        if (empty($template)) {
            $template = $this->_template;
        }
        $temp_var = array_merge($this->_templateVars, $temp_var);

        $this->_view->render($this->_response, $template, $temp_var);
    }

    public function config($key)
    {
        if (isset($this->_ci->get('config')[$key])) {
            return $this->_ci->get('config')[$key];
        }

        $parts = explode('.', $key);
        $config = $this->_ci->get('config');
        foreach ($parts as $key) {
            if (isset($config[$key])) {
                $config =& $config[$key];
            } else {
                return null;
            }
        }

        return $config;
    }

}
