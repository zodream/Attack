<?php
namespace Zodream\Module\Attack\Domain;

use Zodream\Disk\Directory;
use Zodream\Disk\File;
use Zodream\Disk\FileObject;
use Zodream\Disk\Stream;
use Zodream\Debugger\Domain\Log;
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
    protected $rules = [];

    /**
     * 输入和执行搭配木马
     * @var array
     */
    protected $input_output = [
        'php|phtml' =>[
            'input' => '/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|fread|file_get_contents|curl_exec|base64_decode|\$password|\$pwd/i',
            'exec' => '/file_put_contents|eval|assert|include|require|include_once|require_once|create_function|popen|exec|proc_open|passthru|call_user_func|\$[\w_]\s*\(/i',
        ],
        'asp' => [
            'input' => '/request\s*\(|Microsoft\.XMLHTTP/i',
            'exec' => '/ADODB\.Stream|\.SaveToFile|\.Write/i',
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

    /**
     * @return array
     */
    public function getRules() {
        if (empty($this->rules)) {
            $this->rules = include_once '../dict/scan_rules.php';
        }
        return $this->rules;
    }

    public function addRule($rule, $name = null) {
        if (!is_array($rule)) {
            $rule = [$rule => $name];
        }
        $this->rules = array_merge($this->rules, $rule);
        return $this;
    }

    public function setRules(array $rules) {
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
            Log::error('可疑PHP混淆木马');
            return true;
        }
        if ($this->checkAspLine($file)) {
            Log::error('可疑ASP混淆木马');
            return true;
        }
        if (!$this->hasRules($file)) {
            return false;
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
     * 判断是否有检测规则
     * @param File $file
     * @return bool
     */
    protected function hasRules(File $file) {
        return in_array($file->getExtension(), ['php', 'asp', 'phtml']);
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
        return $this->checkLineLength($file, '<?php');
    }

    /**
     * 判断行的长度
     * @param File $file
     * @param $beginTag
     * @return bool
     */
    protected function checkLineLength(File $file, $beginTag) {
        $stream = new Stream($file);
        $is_begin = false;
        $length = 0;
        $result = $this->checkStreamWithCallback($stream, function ($line) use (&$is_begin, &$length, $beginTag) {
            if (!$is_begin && strpos($line, $beginTag) !== false) {
                $is_begin = true;
            }
            if (!$is_begin) {
                return false;
            }
            if (strlen($line) > 1000) {
                return true;
            }
            if (preg_match('#[a-z0-9/\+]{20,}#i', $line, $match)) {
                // 混淆代码截断判断
                $length += strlen($match[0]);
                return false;
            }
            return $length > 1000;
        });
        $stream->close();
        return $result;
    }

    protected function checkAspLine(File $file) {
        if (!in_array($file->getExtension(), ['asp'])) {
            return false;
        }
        return $this->checkLineLength($file, '<%');
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
        $rule = null;
        foreach ($this->input_output as $ext => $item) {
            $ext = explode('|', $ext);
            if (in_array($file->getExtension(), $ext)) {
                $rule = $item;
                break;
            }
        }
        if (empty($rule)) {
            return false;
        }
        $content = $file->read();
        return preg_match($rule['input'], $content, $match) &&
            preg_match($rule['exec'], $content, $match);
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
        return preg_match($rule, $content, $match);
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
        return $this->mapRule(function ($rule, $name) use ($content) {
            if ($this->checkRule($content, $rule)) {
                Log::error(sprintf('内容匹配：%s， %s', $rule, $this->getFormatName($name)));
                return true;
            }
        });
    }

    protected function getFormatName($name) {
        if (!preg_match('#(.*)\[(.*?)\]\[(.*?)\]\[(.*?)\]#', $name, $match)) {
            return '';
        }
        $grade = [
            '可疑',
            '恶意',
            '危险',
        ];
        return sprintf(' %s(%s) %s', $match[1], $match[4], $grade[$match[3]]);
    }

    public function mapRule(callable $callback) {
        foreach ($this->getRules() as $rule => $name) {
            if (true === call_user_func($callback, $rule, $name)) {
                return true;
            }
        }
        return false;
    }


    protected function checkPhpScript($content) {
        // %(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)%
        $encoded_content = $this->getEncodeContent($content);
        if (empty($encoded_content)) {
            return false;
        }
        $encoded_content64 = base64_encode($encoded_content);
        return $this->checkRules($encoded_content64);
    }

    protected function getEncodeContent($content) {
        $counter = 0;
        $encoded_content = preg_replace('/<\?php|\?>|<\?/', '', $content);
        $temp = array();
        if (preg_match('/(\beval\b\(gzinflate|\beval\b\(base64_decode)/', $encoded_content)) {
            while (preg_match('/\beval\((gzinflate|base64_decode)\((.*?)\);/', $encoded_content, $matches)) {
                $encoded_content = preg_replace('/<\?php|\?>|<\?|eval/', '', $encoded_content);
                $temp = $matches;
                if (isset($matches[1]) && isset($matches[2]) && strpos($matches[2], '$') === false) {
                    eval('\$encoded_content = ' . $matches[1] . '(' . $matches[2] . ';');
                } else if (isset($matches[1]) && isset($matches[2]) && strpos($matches[2], '$') !== false) {
                    preg_match('/\$(.*?)\)/', $matches[2], $variable);
                    if (isset($variable[1])) {
                        preg_match('/\$' . $variable[1] . '=(.*?);/', $content, $content_match);
                        if (isset($content_match[1])) {
                            $content_temp = $matches[1] . '(' . str_replace('$' . $variable[1], $content_match[1], $matches[2]);
                            eval('$encoded_content = ' . $content_temp . ';');
                        } else {
                            $encoded_content = '';
                        }
                    } else {
                        $encoded_content = '';
                    }
                } else {
                    $encoded_content = '';
                }
                if ($counter > 20) {
                    //protect from looping
                    break;
                }
                $counter++;
            }
            return $encoded_content;
        }
        if (preg_match('/preg_replace.*\/e"/', $encoded_content)) {
            while (preg_match('/preg_replace\((.*?)\/e(.*)\);/', $encoded_content, $matches)) {
                $encoded_content = preg_replace('/<\?php|\?>|<\?/', '', $encoded_content);
                preg_replace('/preg_replace\((.*?)\/e(.*)\);/', '', $encoded_content);
                if (isset($matches[1]) && isset($matches[2])) {
                    eval('$encoded_content = preg_replace(' . $matches[1] . '/' . $matches[2] . ');');
                }
                if ($counter > 20) {
                    //protect from looping
                    break;
                }
                $counter++;
            }
            return $encoded_content;
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