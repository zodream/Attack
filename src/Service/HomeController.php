<?php
namespace Zodream\Module\Attack\Service;

use Zodream\Module\Attack\Domain\Scanner;
use Zodream\Service\Factory;

class HomeController extends Controller {

    public function indexAction() {

    }

    /**
     * 启动扫描器
     * @param $dir
     * @param null $rule
     * @param null $out
     */
    public function scanAction($dir, $rule = null, $out = null) {
        $scanner = new Scanner();
        if (!empty($rule)) {
            $scanner->setRules(explode(';', $rule));
        }
        if (!empty($out)) {
            $scanner->setOutput(Factory::root()->file($out));
        }
        $scanner->scan(Factory::root()->directory($dir));
    }
}