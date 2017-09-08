<?php

class Profiles
{
    /**
     * @var \Database\Mysql
     */
    protected $_db;

    public function __construct($db)
    {
        $this->_db = $db;
    }

    /**
     * @param array $options
     * @return array
     */
    public function getPage($options = [])
    {
        $totalRows = $this->_db->count($options['conditions']);

        $page = 1;
        $limit = isset($options['size']) ? intval($options['size']) : 25;
        $totalPages = max(ceil($totalRows / $limit), 1);
        if (isset($options['page'])) {
            $page = min(max($options['page'], 1), $totalPages);
        }
        $sort = !empty($options['sort']) ? $options['sort'] : $this->_db->getPk();

        $cursor = $this->_db->paginate($page, $limit, $options['conditions'], $sort);

        return [
            'results' => $this->_wrap($cursor),
            'sort' => $sort,
            'page' => $page,
            'size' => $limit,
            'totalPages' => $totalPages
        ];
    }

    public function getForUrl($url, $options, $conditions = [])
    {
        $conditions = array_merge(
            (array)$conditions,
            ['simple_url' => $url]
        );
        $options = array_merge($options, ['conditions' => $conditions,]);
        return $this->getPage($options);
    }

    /**
     * @return array
     */
    public function findAll()
    {
        return $this->_db->findAll();
    }

    /**
     * @param $id
     * @return array|Profile
     */
    public function get($id)
    {
        $row = $this->_db->findOne(
            [
                'id' => $id
            ]
        );

        return $this->_wrap($row);
    }

    /**
     * @param $data
     * @return array|Profile
     * @throws Exception
     */
    protected function _wrap($data)
    {
        if ($data === null) {
            throw new Exception('No profile data found.');
        }

        if (empty($data)) {
            return [];
        }

        if (count($data) == count($data, 1)) {
            return new Profile($data);
        } else {
            $results = [];
            foreach ($data as $row) {
                $results[] = new Profile($row);
            }
        }

        return $results;
    }
}
