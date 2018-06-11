<?php
namespace Zodream\Module\Attack\Domain\Parser;

class PtyBlock extends Block {

    const TYPE_CONST = 'const',
        TYPE_NONE = '',
        TYPE_STATIC = 'static',
        TYPE_READONLY = 'readonly';


    protected $name;

    protected $value;



    /**
     * @var string
     */
    protected $type = self::TYPE_NONE;

}