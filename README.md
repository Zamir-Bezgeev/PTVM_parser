# Парсер результатов сканирования MaxPatrolVM для DefectDojo

Установка: Создайте папку pt_vm в dojo/tools/, поместите все в файлы в каталог pt_vm. <br><br>
Требования к файлу для загрузки в DefectDojo:<br>
    Тип файла:csv,<br>
    Разделитель=';',<br>
    Обязательные поля (PDQL): ```@Host,host.@Vulners.CVEs,host.@vulners.Description,host.@vulners.HowToFix,host.@Id,host.@vulners.SeverityRating,host.@vulners.CVSS3BaseScore,host.IpAddress```<br>
<br>
Парсер собирает всю информацию в разрезе одна уязвимость - один finding.<br>
Следующие поля используются при формировании finding:<br>
@Host - имя хоста<br>
host.@Id - id хоста из MaxPatrolVM<br>
host.IpAddress - ip адрес хоста<br>
host.@Vulners.CVEs - подтвержденная уязвимость<br>
host.@vulners.Description - описание уязвимости<br>
host.@vulners.HowToFix - метод исправления уязвимости<br>
host.@vulners.SeverityRating - критичность уязвимости<br>
host.@vulners.CVSS3BaseScore - скоринг уязвимости<br>
<br>
![image](https://github.com/user-attachments/assets/4081c18f-eea2-439c-898b-a5ebafd2ed93)
