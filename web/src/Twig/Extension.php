<?php
namespace Twig;

class Extension extends \Twig_Extension
{
    /**
     * @var \Slim\Interfaces\RouterInterface
     */
    private $router;

    /**
     * @var string|\Slim\Http\Uri
     */
    private $uri;

    public function __construct($router, $uri)
    {
        $this->router = $router;
        $this->uri = $uri;
    }

    public function getName()
    {
        return 'xhprof-gui';
    }

    public function getFunctions()
    {
        return [
            'percent' => new \Twig_Function_Method($this, 'makePercent', array(
                'is_safe' => array('html')
            )),
        ];
    }

    public function getFilters()
    {
        return [
            'truncate'  => new \Twig_Filter_Method($this, 'truncate'),
            'as_time'   => new \Twig_Filter_Method($this, 'formatTime', array('is_safe' => array('html'))),
            'as_bytes'  => new \Twig_Filter_Method($this, 'formatBytes', array('is_safe' => array('html'))),
            'as_percent' => new \Twig_Filter_Method($this, 'formatPercent', array('is_safe' => array('html'))),
            'as_diff' => new \Twig_Filter_Method($this, 'formatDiff', array('is_safe' => array('html'))),
        ];
    }

    public function truncate($input, $length = 50)
    {
        if (strlen($input) < $length) {
            return $input;
        }
        return substr($input, 0, $length) . "\xe2\x80\xa6";
    }

    public function formatTime($value)
    {
        return \Util::formatTime($value) . '&nbsp;<span class="units">ms</span>';
    }

    public function formatDiff($value)
    {
        $class = 'diff-same';
        $class = $value > 0 ? 'diff-up' : 'diff-down';
        if ($value == 0) {
            $class = 'diff-same';
        }
        return sprintf(
            '<span class="%s">%s</span>',
            $class,
            number_format((float)$value)
        );
    }

    public function makePercent($value, $total)
    {
        $value = (false === empty($total)) ? $value / $total : 0;
        return $this->formatPercent($value);
    }

    public function formatPercent($value)
    {
        return number_format((float)$value * 100, 2) . ' <span class="units">%</span>';
    }

    public function formatBytes($value)
    {
        return \Util::formatBytes($value) . '&nbsp;<span class="units">MB</span>';
    }

}
