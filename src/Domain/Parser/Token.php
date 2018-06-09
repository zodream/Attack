<?php
namespace Zodream\Module\Attack\Domain\Parser;

use Exception;

/**
 *
 * Value is 2 type variable. It can be string or null
 * When you set value is automatically cast to string
 *
 *
 */
class Token {

    const INVALID_TYPE = -1;
    const INVALID_LINE = -1;
    const INVALID_VALUE = null;
    const INVALID_INDEX = -1;
    /**
     * @var int
     */
    protected $type = self::INVALID_TYPE;
    /**
     * @var string|null
     */
    protected $value;
    /**
     * @var int
     */
    protected $line = self::INVALID_LINE;
    /**
     * Indicate position in current collection
     *
     * @var int
     */
    protected $index = self::INVALID_INDEX;
    /**
     * You need to provide at least 3 elements
     *
     * @param array $data
     * @throws Exception
     */
    public function __construct(array $data = []) {
        if (!empty($data)) {
            $this->setData($data);
        }
    }
    /**
     * @return string
     */
    public function __toString() {
        return $this->assemble();
    }
    /**
     * @return string
     */
    public function assemble() {
        return $this->value !== null ? (string) $this->value : '';
    }


    /**
     * @param array $data
     * @return $this
     * @throws Exception
     */
    protected function setData(array $data) {
        if (!array_key_exists(0, $data)) {
            throw new Exception('Please provide type of token');
        }
        $this->setType((int) $data[0]);
        if (!isset($data[1])) {
            throw new Exception('Please provide value of token');
        }
        $this->setValue($data[1]);
        if (!array_key_exists(2, $data)) {
            throw new Exception('Please provide line of token');
        }
        $this->setLine($data[2]);
        if (array_key_exists(3, $data)) {
            $this->setIndex($data[3]);
        }
        return $this;
    }
    /**
     * @return array
     */
    public function getData() {
        return [$this->getType(), $this->getValue(), $this->getLine(), $this->getIndex()];
    }
    /**
     * @param int $type
     * @return $this
     */
    public function setType($type) {
        $this->type = $type;
        return $this;
    }
    /**
     * @return int
     */
    public function getType(){
        return $this->type;
    }
    /**
     * @return string
     */
    public function getTypeName() {
        return token_name($this->getType());
    }
    /**
     * @return string|null
     */
    public function getValue() {
        return $this->value;
    }
    /**
     * @param string|int $value
     * @throws Exception
     * @return $this
     */
    public function setValue($value) {
        if (!is_string($value) && !is_numeric($value)) {
            throw new Exception('You can set only string. Given: ' . gettype($value));
        }
        $this->value = (string) $value;
        return $this;
    }
    /**
     * @return int
     */
    public function getLine() {
        return $this->line;
    }
    /**
     * @param int $line
     * @return $this
     */
    public function setLine($line) {
        $this->line = $line;
        return $this;
    }
    /**
     * @return bool
     */
    public function isValid() {
        return $this->getValue() !== null;
    }
    /**
     * Remove all data from token so this token become invalid
     *
     * @return $this
     */
    public function remove() {
        $this->type = static::INVALID_TYPE;
        $this->value = static::INVALID_VALUE;
        $this->line = static::INVALID_LINE;
        $this->index = static::INVALID_INDEX;
        return $this;
    }
    /**
     * Add part to the end of value
     *
     * @param string $part
     * @return $this
     * @throws Exception
     */
    public function appendToValue($part) {
        if (!is_string($part) && !is_numeric($part)) {
            throw new Exception('You can append only string to value');
        }
        $this->value = $this->value . $part;
        return $this;
    }
    /**
     * Add part to the begin of value
     *
     * @param string $part
     * @return $this
     * @throws Exception
     */
    public function prependToValue($part) {
        if (!is_string($part) && !is_numeric($part)) {
            throw new Exception('You can prepend only string to value');
        }
        $this->value = $part . $this->value;
        return $this;
    }
    /**
     * @return null|int
     */
    public function getIndex() {
        return $this->index;
    }
    /**
     * @param int $index
     * @return $this
     */
    public function setIndex($index) {
        $this->index = $index;
        return $this;
    }


    public function equal(Token $token) {
        return (
            $this->value === $token->getValue()
            &&
            $this->type === $token->getType()
        );
    }

    /**
     * 是否是脚本 (排除文本，开始结束标记，空白)
     * @return bool
     */
    public function isScript() {
        return !in_array($this->type, [T_INLINE_HTML, T_OPEN_TAG, T_CLOSE_TAG, T_WHITESPACE]);
    }
}