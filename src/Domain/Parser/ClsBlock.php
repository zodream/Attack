<?php
namespace Zodream\Module\Attack\Domain\Parser;

class ClsBlock extends Block {

    const
        TYPE_CLASS = 'class',
        TYPE_INTERFACE = 'interface',
        TYPE_TRAIT = 'trait';

    protected $name;

    /**
     * @var string[]
     */
    protected $uses = [];

    protected $type = self::TYPE_CLASS;

    /** @var bool */
    protected $final = false;
    /** @var bool */
    protected $abstract = false;
    /** @var string|string[] */
    protected $extends = [];
    /** @var string[] */
    protected $implements = [];
    /** @var array[] */
    protected $traits = [];
    /**
     * @var PtyBlock[]
     */
    protected $properties = [];
    /** @var FuncBlock[] name => Method */
    protected $methods = [];



    public function addUse($class, $alias = null) {
        if (empty($alias)) {
            $alias = end(explode('\\', $class));
        }
        $this->uses[$alias] = $class;
        return $this;
    }
}