<?php
namespace Zodream\Module\Attack\Domain\Parser;

use Exception;

class PkgBlock {

    /**
     * @var string
     */
    protected $name;

    /**
     * @var ClsBlock[]
     */
    protected $classes = [];

    /**
     * @param $name
     * @return ClsBlock
     * @throws Exception
     */
    public function addClass($name) {
        if (isset($this->classes[$name])) {
            throw new Exception("Class $name was already added.");
        }
        return $this->classes[$name] = new ClsBlock($name, $this);
    }

    public function addInterface($name) {
        return $this->addClass($name)->setType(ClassType::TYPE_INTERFACE);
    }

    public function addTrait(string $name): ClassType {
        return $this->addClass($name)->setType(ClassType::TYPE_TRAIT);
    }
}