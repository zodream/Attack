<?php
namespace Zodream\Module\Attack\Domain\Parser;


class Block {

    const VISIBILITY_PUBLIC = 'public',
        VISIBILITY_INTERNAL = 'internal',
        VISIBILITY_PROTECTED = 'protected',
        VISIBILITY_PRIVATE = 'private';

    /**
     * @var string
     */
    protected $visibility;

    /**
     * @var string
     */
    protected $comment;
}