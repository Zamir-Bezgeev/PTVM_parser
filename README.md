# Парсер для DefectDojo результатов сканирования MaxPatrolVM

Установка: Создайте папку pt_vm в dojo/tools/, поместите все в файлы в каталог pt_vm.
Требования к файлу для загрузки в DefectDojo:
    Тип файла:csv,
    Разделитель=';',
    Обязательные поля:@Host,host.@Vulners.CVEs,host.@vulners.Description,host.@vulners.HowToFix,host.@Id,host.@vulners.SeverityRating,host.@vulners.CVSS3BaseScore,host.IpAddress

Парсер собирает всю информацию в разрезе одна уязвимость - один finding.
Следующие поля используются при формировании finding:
@Host - имя хоста
host.@Id - id хоста из MaxPatrolVM
host.IpAddress - ip адрес хоста
host.@Vulners.CVEs - подтвержденная уязвимость
host.@vulners.Description - описание уязвимости
host.@vulners.HowToFix - метод исправления уязвимости
host.@vulners.SeverityRating - критичность уязвимости
host.@vulners.CVSS3BaseScore - скоринг уязвимости

![image](https://github.com/user-attachments/assets/4081c18f-eea2-439c-898b-a5ebafd2ed93)
