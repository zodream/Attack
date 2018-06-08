# Attack

根据文件内容进行不安全文件检测

## 使用方法

单模块使用

命令行方式

    php artisan scan --dir=  --rule=  --out=

参数说明

    --dir  检测的文件夹
    
    --rule 自定义正则规则，默认为空使用自带规则
    
    --out 日志保存文件路径，默认不保存