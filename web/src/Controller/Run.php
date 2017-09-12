<?php
namespace Controller;

class Run extends \Controller
{

    public function index()
    {
        $sort = $this->_request->getQueryParam('sort');
        $search = [];
        $keys = ['date_start', 'date_end', 'url'];
        foreach ($keys as $key) {
            if ($this->_request->getQueryParam($key)) {
                $search[$key] = $this->_request->getQueryParam($key);
            }
        }

        $result = $this->_profiles->getPage(
            [
                'sort' => $sort,
                'page' => $this->_request->getQueryParam('page'),
                'size' => $this->config('page.limit'),
                'conditions' => $search,
            ]
        );

        $paging = [
            'total_pages' => $result['totalPages'],
            'page' => $result['page'],
            'sort' => $sort
        ];

        $title = '最近运行';
        $titleMap = [
            'wt' => '执行时间',
            'cpu' => 'CPU时间',
            'mu' => '内存使用'
        ];
        if (isset($titleMap[$sort])) {
            $title = $titleMap[$sort];
        }

        $tpl_var = [
            'paging' => $paging,
            'title' => $title,
            'base_url' => 'home',
            'runs' => $result['results'],
            'date_format' => $this->config('date.format'),
            'search' => $search,
            'has_search' => strlen(implode('', $search)) > 0,
        ];

        $this->render('runs/list.twig', $tpl_var);
    }

    public function view()
    {
        $detailCount = $this->config('detail.count');
        $result = $this->_profiles->get($this->_request->getQueryParam('id'));

        $result->calculateSelf();

        // Self wall time graph
        $timeChart = $result->extractDimension('ewt', $detailCount);

        // Memory Block
        $memoryChart = $result->extractDimension('emu', $detailCount);

        $profile = $result->sort('ewt', $result->getProfile());

        $tpl_var = [
            'title' => '函数监控',
            'result' => $result,
            'wall_time' => $timeChart,
            'memory' => $memoryChart,
            'profile' => $profile,
            'date_format' => $this->config('date.format'),
        ];

        $this->render('runs/view.twig', $tpl_var);
    }

    public function url()
    {
        $pagination = [
            'sort' => $this->_request->getQueryParam('sort'),
            'page' => $this->_request->getQueryParam('page'),
            'size' => $this->config('page.limit'),
        ];

        $search = [];
        $keys = ['date_start', 'date_end', 'limit', 'limit_custom'];
        foreach ($keys as $key) {
            $search[$key] = $this->_request->getQueryParam($key);
        }

        $runs = $this->_profiles->getForUrl(
            $this->_request->getQueryParam('url'),
            $pagination,
            $search
        );

        if (isset($search['limit_custom']) && strlen($search['limit_custom']) > 0 && $search['limit_custom'][0] == 'P') {
            $search['limit'] = $search['limit_custom'];
        }

        $paging = [
            'total_pages' => $runs['totalPages'],
            'sort' => $pagination['sort'],
            'page' => $runs['page']
        ];

        $tpl_var = [
            'paging' => $paging,
            'base_url' => 'url.view',
            'runs' => $runs['results'],
            'url' => $this->_request->getQueryParam('url'),
            'date_format' => $this->config('date.format'),
            'search' => array_merge($search, ['url' => $this->_request->getQueryParam('url')]),
        ];

        $this->render('runs/url.twig', $tpl_var);
    }

    public function symbol()
    {
        $id = $this->_request->getQueryParam('id');
        $symbol = $this->_request->getQueryParam('symbol');

        $profile = $this->_profiles->get($id);
        $profile->calculateSelf();
        list($parents, $current, $children) = $profile->getRelatives($symbol);

        $tpl_var = [
            'symbol' => $symbol,
            'id' => $id,
            'main' => $profile->get('main()'),
            'parents' => $parents,
            'current' => $current,
            'children' => $children
        ];

        $this->render('runs/symbol.twig', $tpl_var);
    }

    public function callgraph()
    {
        $profile = $this->_profiles->get($this->_request->getQueryParam('id'));
        $tpl_var = [
            'title' => '调用图',
            'profile' => $profile,
            'date_format' => $this->config('date.format'),
        ];

        $this->render('runs/callgraph.twig', $tpl_var);
    }

    public function callgraphData()
    {
        $profile = $this->_profiles->get($this->_request->getQueryParam('id'));
        $metric = $this->_request->getQueryParam('metric') ?: 'wt';
        $threshold = (float)$this->_request->getQueryParam('threshold') ?: 0.001;
        $callgraph = $profile->getCallgraph($metric, $threshold);

        return $this->_response->withJson($callgraph);
    }

    public function symbolShort()
    {
        $id = $this->_request->getQueryParam('id');
        $threshold = $this->_request->getQueryParam('threshold');
        $symbol = $this->_request->getQueryParam('symbol');
        $metric = $this->_request->getQueryParam('metric');

        $profile = $this->_profiles->get($id);
        $profile->calculateSelf();
        list($parents, $current, $children) = $profile->getRelatives($symbol, $metric, $threshold);

        $tpl_var = [
            'symbol' => $symbol,
            'id' => $id,
            'main' => $profile->get('main()'),
            'parents' => $parents,
            'current' => $current,
            'children' => $children,
        ];

        $this->render('runs/symbol-short.twig', $tpl_var);
    }

    public function flamegraph()
    {
        $profile = $this->_profiles->get($this->_request->getQueryParam('id'));

        $tpl_var = [
            'profile' => $profile,
            'date_format' => $this->config('date.format'),
        ];

        $this->render('runs/flamegraph.twig', $tpl_var);
    }

    public function flamegraphData()
    {
        $profile = $this->_profiles->get($this->_request->getQueryParam('id'));
        $metric = $this->_request->getQueryParam('metric') ?: 'wt';
        $threshold = (float)$this->_request->getQueryParam('threshold') ?: 0.001;
        $flamegraph = $profile->getFlamegraph($metric, $threshold);

        return $this->_response->withJson($flamegraph);
    }

    public function compare()
    {
        $baseRun = $headRun = $candidates = $comparison = null;
        $paging = [];

        if ($this->_request->getQueryParam('base')) {
            $baseRun = $this->_profiles->get($this->_request->getQueryParam('base'));
        }

        if ($baseRun && !$this->_request->getQueryParam('head')) {
            $pagination = [
                'sort' => $this->_request->getQueryParam('sort'),
                'page' => $this->_request->getQueryParam('page'),
                'limit' => $this->config('page.limit'),
            ];

            $candidates = $this->_profiles->getForUrl(
                $baseRun->getMeta('simple_url'),
                $pagination
            );

            $paging = [
                'total_pages' => $candidates['totalPages'],
                'sort' => $pagination['sort'],
                'page' => $candidates['page']
            ];
        }

        if ($this->_request->getQueryParam('head')) {
            $headRun = $this->_profiles->get($this->_request->getQueryParam('head'));
        }

        if ($baseRun && $headRun) {
            $comparison = $baseRun->compare($headRun);
        }

        $tpl_var = [
            'base_url' => 'run.compare',
            'base_run' => $baseRun,
            'head_run' => $headRun,
            'candidates' => $candidates,
            'url_params' => $this->_request->getQueryParams(),
            'date_format' => $this->config('date.format'),
            'comparison' => $comparison,
            'paging' => $paging,
            'search' => [
                'base' => $this->_request->getQueryParam('base'),
                'head' => $this->_request->getQueryParam('head'),
            ]
        ];

        $this->render('runs/compare.twig', $tpl_var);
    }

}
