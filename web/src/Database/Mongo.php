<?php
namespace Database;

use \MongoDB\Driver\Manager;
use \MongoDB\Driver\Query;
use \MongoDB\BSON\ObjectId;
use \MongoDB\BSON\UTCDateTime;

class Mongo implements DbInterface
{

    /**
     * @var \MongoDB\Driver\Manager
     */
    protected $_manager;

    protected $_db;

    protected $_collection;

    public function __construct($host, $options, $db, $collection) {
        try {
            $this->_manager = new Manager($host, $options);
            $this->_db = $db;
            $this->_collection = $collection;
        } catch (\MongoException $e) {
            throw new \Exception($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param array $conditions
     * @return mixed
     */
    public function count(array $conditions = [])
    {
        $opts = $this->_conditions($conditions);
        $query = new Query($opts);
        $cursor = $this->_manager->executeQuery($this->_dbname(), $query);
        $count  = 0;

        foreach ($cursor as $document) {
            $count++;
        }

        return $count;
    }

    public function paginate($page, $limit, array $conditions = [], $sort = '', $direction = 'DESC')
    {
        $filter = $this->_conditions($conditions);
        $options = [
            'limit' => $limit,
            'skip' => ($page - 1) * $limit,
        ];
        $this->_setSort($options, $sort, $direction);

        $query = new Query($filter, $options);
        $cursor = $this->_manager->executeQuery($this->_dbname(), $query);
        return $this->_format($cursor);
    }

    public function findOne($id)
    {
        $filter = ['_id' => new ObjectId($id)];
        $options = [];
        $query = new Query($filter, $options);
        $cursor = $this->_manager->executeQuery($this->_dbname(), $query); // $mongo contains the connection object to MongoDB
        return current($this->_format($cursor));
    }

    /**
     * 删除的操作
     * @param string $id 删除的id
     * @return \MongoDB\Driver\WriteResult
     * @author zengye
     * @since 20210729 10:28
     */
    public function Del($id)
    {

        $bulk = new \MongoDB\Driver\BulkWrite;
        $filter = ['_id' => new ObjectId($id)];
        $bulk->delete($filter, ['limit' => 0]);   // limit 为 0 时，删除所有匹配数据
        $writeConcern = new \MongoDB\Driver\WriteConcern(\MongoDB\Driver\WriteConcern::MAJORITY, 1000);
        $result = $this->_manager->executeBulkWrite($this->_dbname(), $bulk, $writeConcern);
        return $result;
    }

    public function findAll(array $conditions = [])
    {
        //
    }

    protected function _setSort(&$options, $sort, $direction)
    {
        if ($sort == 'id') {
            $sort = '_id';
        }

        if (strlen($sort)) {
            $options['sort'] = [
                $sort => $direction == 'ASC' ? 1 : -1
            ];
        }
    }

    protected function _dbname()
    {
        return $this->_db . '.' . $this->_collection;
    }

    protected function _conditions($search)
    {
        if (!empty($search['limit_custom']) && $search['limit_custom'][0] == "P") {
            $search['limit'] = $search['limit_custom'];
        }
        $hasLimit = (!empty($search['limit']) && $search['limit'] != -1);

        $conditions = [];
        if (!empty($search['date_start']) && !$hasLimit) {
            $conditions['meta.request_date']['$gte'] = strtotime($search['date_start']);
        }

        if (!empty($search['date_end']) && !$hasLimit) {
            $conditions['meta.request_date']['$lte'] = strtotime($search['date_end']);
        }

        if (isset($search['simple_url'])) {
            $conditions['meta.simple_url'] = (string)$search['simple_url'];
        }

        if ($hasLimit && $search['limit'][0] == "P") {
            $date = new \DateTime();
            try {
                $date->sub(new \DateInterval($search['limit']));
                $conditions['meta.request_date']['$gte'] = new UTCDateTime($date->getTimestamp());
            } catch (\Exception $e) {
                // Match a day in the future so we match nothing, as it's likely an invalid format
                $conditions['meta.request_date']['$gte'] = new UTCDateTime(time() + 86400);
            }
        }

        if (isset($search['url'])) {
            // Not sure if letting people use regex here
            // is a good idea. Only one way to find out.
            $conditions['meta.url'] = array(
                '$regex' => (string)$search['url'],
                '$options' => 'i',
            );
        }

        return $conditions;
    }

    protected function _format($cursor)
    {
        $result = [];
        foreach ($cursor as $document) {
            $_id = sprintf("%s", $document->_id);
            unset($document->_id);

            $result[] = array_merge(['id' => $_id], json_decode(json_encode($document), true));
        }

        return $result;
    }
}