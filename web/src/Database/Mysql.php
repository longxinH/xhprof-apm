<?php
namespace Database;

use Slim\PDO\Statement\SelectStatement;
use Slim\PDO\Statement\StatementContainer;
use Slim\PDO\Database;

class Mysql implements DbInterface
{

    /**
     * @var \Slim\PDO\Database
     */
    protected $_dbh;

    protected $_dbname;

    public function __construct($dbhost, $username, $password, $dbname, $dbcharset = 'utf8') {
        try {
            $dsn = 'mysql:dbname=' . $dbname . ';host=' . $dbhost . ';charset=' . $dbcharset;
            $this->_dbname = $dbname;
            $this->_dbh = new Database($dsn, $username, $password);
        } catch (\PDOException $e) {
            throw new \Exception($e->getMessage(), $e->getCode());
        }
    }

    /**
     * @param array $conditions
     * @return mixed
     */
    public function count(array $conditions = [])
    {
        $selectStatement = $this->_dbh->select([])->from($this->_dbname)->count();
        $this->_conditions($selectStatement, $conditions);
        $totalRows = $selectStatement->execute()->fetch();

        return current($totalRows);
    }

    public function paginate($page, $limit, array $conditions = [], $sort = '', $direction = 'DESC')
    {
        $selectStatement = $this->_dbh->select()->from($this->_dbname)->orderBy($sort, $direction)->limit($limit, ($page - 1) * $limit);
        $this->_conditions($selectStatement, $conditions);
        $list = $selectStatement->execute()->fetchAll();

        return $this->_format($list);
    }

    public function findOne($id)
    {
        $selectStatement = $this->_dbh->select()->from($this->_dbname);
        $selectStatement->where('id', '=', $id);
        $row = $selectStatement->execute()->fetch();
        return $this->_format($row);
    }

    public function findAll(array $conditions = [])
    {
        $selectStatement = $this->_dbh->select()->from($this->_dbname);

        foreach ($conditions as $column => $val) {
            $selectStatement->where($column, '=', $val);
        }

        $list = $selectStatement->execute()->fetchAll();
        return $this->_format($list);
    }

    /**
     * @param array $columns
     * @param string $table
     * @return SelectStatement
     */
    public function select(array $columns = array('*'), $table = '')
    {
        $table = $table ? $table : $this->_dbname;
        return $this->_dbh->select($columns)->from($table);
    }

    protected function _conditions(StatementContainer $stmt, $search)
    {
        if (!empty($search['limit_custom']) && $search['limit_custom'][0] == "P") {
            $search['limit'] = $search['limit_custom'];
        }
        $hasLimit = (!empty($search['limit']) && $search['limit'] != -1);

        if (!empty($search['date_start']) && !$hasLimit) {
            $stmt->where('date', '>=', strtotime($search['date_start']));
        }

        if (!empty($search['date_end']) && !$hasLimit) {
            $stmt->where('date', '<=', strtotime($search['date_end']));
        }

        if (isset($search['url'])) {
            $stmt->whereLike('url', '%' . $search['url'] . '%');
        }

        if (isset($search['simple_url'])) {
            $stmt->where('simple_url', '=', trim($search['simple_url']));
        }

        if ($hasLimit && $search['limit'][0] == "P") {
            $date = new \DateTime();
            try {
                $date->sub(new \DateInterval($search['limit']));
                $stmt->where('date', '>=', $date->getTimestamp());
            } catch (\Exception $e) {
                $stmt->where('date', '>=', time() + 86400);
            }
        }

    }

    protected function _format($list)
    {
        if (empty($list)) {
            return [];
        }

        $result = [];
        if (count($list) == count($list, 1)) {
            $result = array_merge($list, json_decode($list['export'], true));
            unset($result['export']);
        } else {
            foreach ($list as $row) {
                $row = array_merge($row, json_decode($row['export'], true));
                unset($row['export']);

                $result[] = $row;
            }
        }

        return $result;
    }
}