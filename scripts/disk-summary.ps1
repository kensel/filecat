param([string]$Catalog = "catalogs/isos.jsonl")
$disks = Get-Content $Catalog | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object kind -eq 'disk'
"`n== By format =="
$disks | Group-Object { $_.probe.format } | Sort-Object Count -Descending | Select-Object Count, Name,
  @{n='GB'; e={[math]::Round(($_.Group | Measure-Object size -Sum).Sum / 1GB, 1)}} | Format-Table -AutoSize
"== Each image =="
$disks | Sort-Object size -Descending | Select-Object `
  @{n='GB';      e={[math]::Round($_.size / 1GB, 2)}},
  @{n='format';  e={$_.probe.format + $(if ($_.probe.variant) {"/" + $_.probe.variant})}},
  @{n='virtGB';  e={if ($_.probe.virtual_size) {[math]::Round($_.probe.virtual_size / 1GB, 1)}}},
  @{n='fs';      e={($_.probe.filesystems | ForEach-Object type | Select-Object -Unique) -join ','}},
  @{n='os';      e={$_.probe.os_hint}},
  @{n='files';   e={$_.probe.members_count}},
  @{n='label';   e={$_.probe.volume_id}},
  rel_path | Format-Table -AutoSize -Wrap
