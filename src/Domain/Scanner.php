<?php
namespace Zodream\Module\Attack\Domain;

use Zodream\Disk\Directory;
use Zodream\Disk\File;
use Zodream\Disk\FileObject;
use Zodream\Disk\Stream;
use Zodream\Helpers\Arr;
use Zodream\Infrastructure\Http\Request;
use Exception;
use Zodream\Module\Attack\Domain\Parser\PhpParser;

/**
 * Created by PhpStorm.
 * User: zx648
 * Date: 2017/3/17
 * Time: 18:25
 */
class Scanner {

    /**
     * 安全扫描规则
     * @var array
     */
    protected $rules = [
        'php' => [
            '(\$_(GET|POST|REQUEST)\[.{0,15}\]\s{0,10}\(\s{0,10}\$_(GET|POST|REQUEST)\[.{0,15}\]\))',
            '((eval|assert)(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
            '(eval(\s|\n)*\(base64_decode(\s|\n)*\((.|\n){1,200})',
            '(function\_exists\s*\(\s*[\'|\"](popen|exec|proc\_open|passthru)+[\'|\"]\s*\))',
            '((exec|shell\_exec|passthru)+\s*\(\s*\$\_(\w+)\[(.*)\]\s*\))',
            '(\$(\w+)\s*\(\s.chr\(\d+\)\))',
            '(\$(\w+)\s*\$\{(.*)\})',
            '(\$(\w+)\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\s*\))',
            '(\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\(\s*\$(.*)\))',
            '(\$\_\=(.*)\$\_)',
            '(\$(.*)\s*\((.*)\/e(.*)\,\s*\$\_(.*)\,(.*)\))',
            '(new com\s*\(\s*[\'|\"]shell(.*)[\'|\"]\s*\))',
            '(echo\s*curl\_exec\s*\(\s*\$(\w+)\s*\))',
            '((fopen|fwrite|fputs|file\_put\_contents)+\s*\((.*)\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\](.*)\))',
            '(\(\s*\$\_FILES\[(.*)\]\[(.*)\]\s*\,\s*\$\_(GET|POST|REQUEST|FILES)+\[(.*)\]\[(.*)\]\s*\))',
            '(\$\_(\w+)(.*)(eval|assert|include|require|include\_once|require\_once)+\s*\(\s*\$(\w+)\s*\))',
            '((include|require|include\_once|require\_once)+\s*\(\s*[\'|\"](\w+)\.(jpg|gif|ico|bmp|png|txt|zip|rar|htm|css|js)+[\'|\"]\s*\))',
            '(eval\s*\(\s*\(\s*\$\$(\w+))',
            '((eval|assert|include|require|include\_once|require\_once|array\_map|array\_walk)+\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)+\[(.*)\]\s*\))',
            '(preg\_replace\s*\((.*)\(base64\_decode\(\$)',
            '(?<![a-z0-9_])eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))',
            'fopen\(\s*\$_(POST|GET|REQUEST)'
        ],
        'asp' => [
            '<%(execute|eval)\s*request(.+)%>'
        ]
    ];
    /**
     * @var Stream
     */
    protected $output;

    public function setOutput($stream) {
        $this->output = $stream instanceof Stream ? $stream : new Stream($stream);
        return $this;
    }

    public function addRule($rule, $type = 'php') {
        if (!is_array($rule)) {
            $rule = [$rule];
        }
        if (!isset($this->rules[$type])) {
            $this->rules[$type] = [];
        }
        $this->rules[$type] = array_merge($this->rules[$type], $rule);
        return $this;
    }

    public function setRules(array $rules) {
        if (!Arr::isMultidimensional($rules)) {
            $rules = [
                'php' => $rules
            ];
        }
        $this->rules = $rules;
        return $this;
    }

    public function scan(Directory $root) {
        $root->map(function (FileObject $file) {
            if ($file instanceof Directory) {
                $this->scan($file);
                return;
            }
            if ($this->check($file)) {
                $this->addErrorFile($file);
            }
        });
    }


    public function check(File $file) {
        // 以1M为分割点
        if ($file->size() < 1000000) {
            $content = $file->read();
            return $this->checkRules($content);
        }
        $stream = new Stream($file);
        $result = $this->checkStream($stream);
        $stream->close();
        return $result;
    }

    public function checkPHP($content) {
        $parser = new PhpParser($content);
        if (!$parser->isScript()) {
            return false;
        }
    }

    public function checkStream(Stream $stream) {
        try {
            $stream->open('r');
            while (!$stream->isEnd()) {
                $line = $stream->readLine();
                if (empty($line)) {
                    continue;
                }
                if ($this->checkRules($line)) {
                    return true;
                }
            }
        } catch (Exception $ex) {
            return false;
        }
        return false;
    }

    public function checkRule($content, $rule) {
        return preg_match(sprintf('#%s#i', $rule), $content, $match);
    }

    /**
     * @param $content
     * @return bool
     */
    public function checkRules($content) {
        foreach ($this->rules as $rules) {
            foreach ($rules as $rule) {
                if (empty($rule)) {
                    continue;
                }
                if ($this->checkRule($content, $rule)) {
                    return true;
                }
            }
        }
        return false;
    }

    public function addErrorFile(File $file) {
        if (Request::isCli()) {
            echo (string)$file,PHP_EOL;
        }
        if ($this->output) {
            $this->output->writeLine($file);
        }
    }

    public function __destruct() {
        if ($this->output) {
            $this->output->close();
        }
    }
}