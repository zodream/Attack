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
     */
    public function scanAction($dir, $rule = null) {
        $scanner = new Scanner();
        $scanner->setRules(explode(';', $rule));
        $scanner->scan(Factory::root()->directory($dir));
    }
}