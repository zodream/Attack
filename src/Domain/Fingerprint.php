<?php
namespace Zodream\Module\Attack\Domain;


use Zodream\Http\Uri;

class Fingerprint {

    /**
     * 安全扫描规则
     * @var array
     */
    protected $rules = [];

    /**
     * @return array
     */
    public function getRules() {
        if (empty($this->rules)) {
            $this->rules = include_once '../dict/web_map.php';
        }
        return $this->rules;
    }

    public function check(Uri $uri) {
        foreach ($this->getRules() as $rule) {
            $content = file_get_contents((string)$uri->addPath($rule));
            if (empty($content)) {
                continue;
            }
            if (isset($rule['md5']) && md5($content) == $rule['md5']) {
                return $rule['name'];
            }
            if (isset($rule['regex']) && preg_match(sprintf('#%s#i', $rule['regex']), $content)) {
                return $rule['name'];
            }
        }
        return false;
    }

}