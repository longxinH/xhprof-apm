<?php
namespace Database;

use Slim\PDO\Statement\SelectStatement;
use Slim\PDO\Statement\StatementContainer;
use Slim\PDO\Database;

class Mysql
{

    /**
     * @var \Slim\PDO\Database
     */
    protected $_dbh;

    protected $_dbname;

    protected $_pk;

    public function __construct($dbhost, $username, $password, $dbname, $dbcharset = 'utf8') {
        try {
            $dsn = 'mysql:dbname=' . $dbname . ';host=' . $dbhost . ';charset=' . $dbcharset;
            $this->_dbname = $dbname;
            $this->_dbh = new Database($dsn, $username, $password);
            $this->_pk = $this->_dbh->query("show keys from {$dbname} where key_name = 'PRIMARY'")->fetch()['Column_name'];
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
        return $selectStatement->execute()->fetchAll();
    }

    public function findOne(array $conditions = [])
    {
        $selectStatement = $this->_dbh->select()->from($this->_dbname);

        foreach ($conditions as $column => $val) {
            $selectStatement->where($column, '=', $val);
        }

        return $selectStatement->execute()->fetch();
    }

    public function findAll(array $conditions = [])
    {
        $selectStatement = $this->_dbh->select()->from($this->_dbname);

        foreach ($conditions as $column => $val) {
            $selectStatement->where($column, '=', $val);
        }

        return $selectStatement->execute()->fetchAll();
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

    public function getPk()
    {
        return $this->_pk;
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
}