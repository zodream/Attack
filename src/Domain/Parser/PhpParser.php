<?php
namespace Zodream\Module\Attack\Domain\Parser;

class PhpParser {

    /**
     * @var Token[]
     */
    protected $items = [];

    public function __construct($content = []) {
        $this->setTokens($content);
    }

    public function setTokens($tokens) {
        if (empty($tokens)) {
            return $this;
        }
        if (is_string($tokens)) {
            $tokens = self::converterTokens($tokens);
        }
        $this->items = $tokens;
        return $this;
    }

    public function next() {
        foreach ($this->items as $token) {
            yield $token;
        }
    }

    public function clean() {
        $data = [];
        foreach ($this->items as $token) {
            if (!$token->isScript()) {
                continue;
            }
            $data[] = $token;
        }
        $this->items = $data;
        return $this;
    }

    public function getFunc() {
        $data = [];
        for ($i = count($this->items) - 1; $i > 0; $i --) {
            if ($this->items[$i]->getType() != T_FUNCTION) {
                continue;
            }
            // 判断是否是匿名函数
            if ($this->items[$i + 1]->getType() == T_WHITESPACE
                && $this->items[$i + 2]->getType() == T_STRING) {
                $data[] = $this->items[$i + 2]->getValue();
            }
        }
        return $data;
    }

    public function getClass() {
        $data = [];
        for ($i = count($this->items) - 1; $i > 0; $i --) {
            if ($this->items[$i]->getType() == T_CLASS) {
                $data[] = $this->items[$i + 2]->getValue();
            }
        }
        return $data;
    }

    /**
     * 是否含有脚本代码
     * @return bool
     */
    public function isScript() {
        foreach ($this->items as $token) {
            if (!$token->isScript()) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $code
     * @return Token[]
     */
    public static function converterTokens($code) {
        try {
            $tokens = token_get_all($code, TOKEN_PARSE);
        } catch (\ParseError $e) {
            // with TOKEN_PARSE flag, the function throws on invalid code
            // let's just ignore the error and tokenize the code without the flag
            $tokens = token_get_all($code);
        }
        foreach ($tokens as $index => $tokenData) {
            if (!is_array($tokenData)) {
                $previousIndex = $index - 1;
                /** @var Token $previousToken */
                $previousToken = $tokens[$previousIndex];
                $line = $previousToken->getLine()
                    + substr_count($previousToken->getValue(), "\n");
                $tokenData = [
                    Token::INVALID_TYPE,
                    $tokenData,
                    $line,
                ];
            }
            $token = new Token($tokenData);
            $token->setIndex($index);
            $tokens[$index] = $token;
        }
        return $tokens;
    }

    public function getDangerousScore() {
        $args = [
            '$_GET',
            '$_POST',
            '$_REQUEST',
            '$_COOKIE',
            '$_SERVER',
            '$_FILES',
            'eval',
            'assert',
            'base64_decode',
            'popen',
            'exec',
            'proc_open',
            'passthru',
            'shell_exec',
            'curl_exec',
            'fopen',
            'fwrite',
            'fputs',
            'file_put_contents',
            'include',
            'require',
            'include_once',
            'require_once',
            'preg_replace',
            'str_replace'
        ];
    }
}