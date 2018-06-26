<?php
namespace Zodream\Module\Attack\Domain;

use Zodream\Disk\Directory;
use Zodream\Disk\File;
use Zodream\Disk\FileObject;
use Zodream\Disk\Stream;
use Zodream\Domain\Debug\Log;
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
            //'(\$(\w+)\s*\$\{(.*)\})',
            '(\$(\w+)\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\s*\))',
            '(\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\(\s*\$(.*)\))',
            //'(\$\_\=(.*)\$\_)',
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
        // 第一步比较文件信息
        $result = $this->mapRule(function ($rule) use ($file) {
            if ($this->checkFileRule($file, $rule)) {
                return true;
            }
        });
        if ($result) {
            return true;
        }
        return $this->checkFileContent($file);
    }

    public function checkFileContent(File $file) {
        if ($this->checkAWordFile($file)) {
            Log::error('一句话木马');
            return true;
        }
        if ($this->checkImageFile($file)) {
            Log::error('图片木马');
            return true;
        }
        if ($this->checkPhpLine($file)) {
            Log::error('可疑混淆木马');
            return true;
        }
        // 第二步比较特征值 以1M为分割点
        if ($file->size() < 1000000) {
            $content = $file->read();
            return $this->checkRules($content);
        }
        if ($file->size() > 20000000) {
            return false;
        }
        $stream = new Stream($file);
        $result = $this->checkStream($stream);
        $stream->close();
        return $result;
    }

    /**
     * 验证文件每行的长度
     * @param File $file
     * @return bool
     */
    protected function checkPhpLine(File $file) {
        if (!in_array($file->getExtension(), ['php', 'phtml'])) {
            return false;
        }
        $stream = new Stream($file);
        $is_php = false;
        $result = $this->checkStreamWithCallback($stream, function ($line) use (&$is_php) {
            if (!$is_php && strpos($line, '<?php') !== false) {
                $is_php = true;
            }
            if (!$is_php) {
                return false;
            }
            if (strlen($line) > 1000) {
                return true;
            }
        });
        $stream->close();
        return $result;
    }

    /**
     * 验证一句话木马，没混淆的
     * @param File $file
     * @return bool
     */
    protected function checkAWordFile(File $file) {
        if ($file->size() > 1000) {
            return false;
        }
        $content = $file->read();
        $input_maps = '/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|fread|file_get_contents|curl_exec|base64_decode/';
        $exec_maps = '/file_put_contents|eval|assert|include|require|include_once|require_once|create_function|popen|exec|proc_open|passthru|call_user_func|\$[\w_]\s*\(/';
        return preg_match($input_maps, $content, $match) &&
            preg_match($exec_maps, $content, $match);
    }

    /**
     * 图片有脚本必定是木马
     * @param File $file
     * @return bool
     */
    protected function checkImageFile(File $file) {
        if (!in_array($file->getExtension(), ['png', 'jpg', 'jpeg', 'bmp', 'ico', 'webp'])) {
            return false;
        }
        $stream = new Stream($file);
        $result = $this->checkStreamWithCallback($stream, function ($line) {
            return strpos($line,'<?php') !== false;
        });
        $stream->close();
        return $result;
    }

    /**
     * 比较危险程度
     * @param $content
     * @return bool
     */
    public function checkPHP($content) {
        $parser = new PhpParser($content);
        if (!$parser->isScript()) {
            return false;
        }

    }

    public function checkStream(Stream $stream) {
        return $this->checkStreamWithCallback($stream, function ($line) {
           return $this->checkRules($line);
        });
    }

    public function checkStreamWithCallback(Stream $stream, callable $callback) {
        try {
            $stream->open('r');
            $index = -1;
            while (!$stream->isEnd()) {
                $index ++;
                $line = $stream->readLine();
                if (empty($line)) {
                    continue;
                }
                if ($callback($line, $index)) {
                    Log::error(sprintf('Line: %s', $index));
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

    public function checkFileRule(File $file, $rule) {
        if (strpos($rule, ':') === false) {
            return false;
        }
        list($tag, $rule) = explode(':', $rule, 2);
        if ($tag == 'name') {
            return $this->checkRule($file->getName(), $rule);
        }
        if ($tag == 'md5') {
            return $file->md5() === $rule;
        }
        if ($tag == 'date') {
            return $this->checkFileTime($file->modifyTime(),
                $rule.' 00:00:00', $rule.' 23:59:59');
        }
        if ($tag == 'time') {
            $args = explode(',', $rule);
            return $this->checkFileTime($file->modifyTime(), $args[0],
                isset($args[1]) ? $args[1] : null);
        }
        return false;
    }

    protected function checkFileTime($modify, $start_at = null, $end_at = null) {
        if (!empty($start_at)) {
            $start_at = strtotime($start_at);
        }
        if (!empty($end_at)) {
            $end_at = strtotime($end_at);
        }
        if (empty($start_at) && empty($end_at)) {
            return false;
        }
        if (empty($start_at)) {
            return $modify <= $end_at;
        }
        if (empty($end_at)) {
            return $modify >= $start_at;
        }
        return $modify >= $start_at && $modify <= $end_at;
    }

    /**
     * @param $content
     * @return bool
     */
    public function checkRules($content) {
        return $this->mapRule(function ($rule) use ($content) {
            if ($this->checkRule($content, $rule)) {
                Log::error('内容匹配：'.$rule);
                return true;
            }
        });
    }

    public function mapRule(callable $callback) {
        foreach ($this->rules as $rules) {
            foreach ($rules as $rule) {
                if (empty($rule)) {
                    continue;
                }
                if (true === call_user_func($callback, $rule)) {
                    return true;
                }
            }
        }
        return false;
    }

    public function addErrorFile(File $file) {
        Log::notice((string)$file);
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