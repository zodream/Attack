<?php
namespace Zodream\Module\Attack\Domain\Parser;

class FuncBlock extends Block {

    protected $body = '';
    /** @var bool */
    protected $static = false;
    /** @var bool */
    protected $final = false;
    /** @var bool */
    protected $abstract = false;

    /** @var string|null  public|protected|private */
    protected $visibility;

}