<?php
namespace Database;

interface DbInterface
{
    public function count();

    public function paginate($page, $limit);

    public function findOne($id);

    public function findAll();
}
