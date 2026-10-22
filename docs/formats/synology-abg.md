# Synology Active Backup for Google Workspace task layout

What is known about how Active Backup for Google Workspace (ABG) stores a
backup task on the NAS, written so that a reader or explorer can be built
without Synology's software. Synology does not publish the layout.

filecat itself only needs part of this (`src/filecat/backup/abg.py`): it
lists the task, reads the task, account and log databases and each user's
item databases, and checks the items against the listing. Everything else
here is for a future reader.

Unlike Active Backup for Business PC backups or Hyper Backup, ABG keeps no
chunk pool: every message, attachment, event, contact and Drive file is an
ordinary file, either named after the item's Google id (mail, calendar,
contacts) or under its own name (Drive). An explorer needs no
decompression, only the databases below and JSON.

## Sources and confidence

| tag | meaning |
|---|---|
| **[F]** | checked here, against the task examined (see below) |
| **[S]** | Synology's published specification for ABG |
| **[I]** | inferred from the data, not proven |
| **[?]** | unknown |

- Synology, "Active Backup for Google Workspace" specification (DSM 7.4):
  <https://www.synology.com/en-us/dsm/7.4/software_spec/abg>. Says Google
  Docs, Sheets and Slides are stored as `.docx`, `.xlsx` and `.pptx`, Forms
  as `.zip` (10 MB limit), Drawings as `.jpeg`, Apps Script as `.json` and
  Jamboard as `.pdf`; that names containing `#SynoVersionRepo`, `#SynoRepo`
  or `#SynoVersions`, names over 255 characters (143 on an encrypted
  destination) are renamed, and paths over 4,016 characters skipped; that
  identical files and mail and calendar attachments are stored once
  ("single instancing"), and Drive files on Btrfs are deduplicated against
  their earlier versions; and that versions are kept for a set period or
  forever [S].
- No third-party description of the layout was found.

### Task examined [F]

| | |
|---|---|
| share | `ActiveBackupforBusiness` on a DSM NAS, beside `@ActiveBackup` (PC backups) and `ActiveBackupForMicrosoft365` |
| task folder | `ActiveBackupForGoogleWorkspace/task_1` |
| `task-config.sqlite` version | 13 |
| task | one domain, 50 users, backing up continuously since 2025-11-15 (33 550 runs by 2026-10-19) |
| items | 683 462 messages (27 274 deleted in Google and kept), 17 591 calendar event versions, 4 165 contact versions, 1 088 Drive files with 1 159 versions |
| size | 101.5 GB in 1 432 417 files (mail 64.8 GB, Drive 17.2 GB + 17.2 GB of versions, databases 2.3 GB); `account.sqlite` counts 82.0 GB |

## 1. Conventions

- Times in the databases are Unix seconds, UTC [F]. `end_time =
  4294967295` (2^32 - 1) means "still current in Google"; any other value is
  when ABG saw the item deleted or replaced [F].
- Every database is SQLite and has a `config_table(key, value)` whose
  `version` row is the schema version [F].
- JSON files are written with tabs and a leading newline, keys sorted [F].
- Secrets: `account.sqlite.user_info_table.access_token` holds each user's
  OAuth access token and `task-config.sqlite.task_info_table.enc_private_key`
  an encrypted service-account key [F]. A reader must not copy them out.

## 2. Directory tree [F]

```
ActiveBackupForGoogleWorkspace/
  task_<n>/                                  one folder per ABG task
    @ActiveBackupGSuite-Databases/
      task-config.sqlite  account.sqlite  team-drive.sqlite
      service-log.sqlite  user-log.sqlite
      mail-log.sqlite  calendar-log.sqlite  contact-log.sqlite  file-log.sqlite
      index-job.sqlite  lazy-update-job-data.sqlite
      single-instancing.db/                  LevelDB (section 6)
      <user id>/                             one per user (Google's numeric id)
        mail.sqlite  mail-label.sqlite  mail-cached.sqlite  mail-unfinished-event.sqlite
        calendar.sqlite  calendar-event.sqlite  calendar-cached-event.sqlite
        calendar-unfinished-event.sqlite
        contact.sqlite  contact-group.sqlite
        drive-unfinished-event.sqlite  index-data.sqlite
        mail-content-search/  calendar-content-search/  contact-content-search/
                                             Lucene 2.x-style indexes (.fdt .fdx .frq
                                             .prx .tis .tii .nrm .fnm) for the
                                             portal's search
    <user folder>/                           user_repo_name, normally the email address
      Mail/<XX>/<YY>/<message id>/v<ver>-<k>-<part>
      Calendar/<XX>/<YY>/<name, cut every 64 chars>/v<ver>-<k>-<part>
      Contact/<XX>/<YY>/<name>/v<ver>-<k>-<part>
      MyDrive/<path as in Drive>
      MyDrive/#SynoVersionRepo/<path>/#SynoVersions/...
      MyDrive/#SynoRepo/id-path-mapping.db/  LevelDB
```

- `<XX>/<YY>` are two levels of upper-case hex bucket folders spreading the
  items. The function that picks them is unknown [?]: it is not MD5, SHA-1,
  SHA-256, CRC32, Adler-32, FNV-1(a) or djb2 of the id or the encoded name.
  A reader does not need it: list the bucket folders and match on the item
  folder's name.
- Shared drives (`team-drive.sqlite`, with `local_name` per drive) were
  enabled for auto-add but there were none, so their location is unknown
  [?]. Expect a Drive-style tree with its own `#SynoVersionRepo` [I].

## 3. Databases

### 3.1 `task-config.sqlite` — `task_info_table` [F]

One row per task: `task_id`, `timestamp` (created), `task_name`,
`backup_policy` (0 seen; the task ran every ~10 minutes, so 0 is probably
continuous [I]), `schedule_id`, `schedule_json` (`{"date", "hour",
"minute", "repeat_hour", "week_day", ...}`), `enable_schedule`,
`enable_dedup`, `enable_auto_add_{drive,mail,contact,calendar,team_drive}`,
`enable_self_service`, `retention_policy` (0 seen) and `retention_days` (30
seen, apparently unused with policy 0: items deleted in Google more than 30
days earlier were still kept [I]), `local_used_storage`, `enc_private_key`
(secret), `admin_unique_id` and `admin_primary_email` (the admin account
the task authenticates as), `domain`.

### 3.2 `account.sqlite` [F]

`user_info_table`, one row per user:

| column | meaning |
|---|---|
| `user_id` | Google's numeric user id; the name of the user's database folder |
| `name`, `email`, `department` | from the directory |
| `account_status` | 1 active; -2 seen on a user deleted from the domain, whose runs failed with "The email address is invalid" and whose services were disabled [F] |
| `dsm_uid` | the DSM user the portal maps them to; 4294967295 when none |
| `user_repo_name` | the user's folder under the task |
| `local_used_storage` | bytes, = the sum of the four below |
| `drive_used_storage`, `mail_used_storage`, `contact_used_storage`, `calendar_used_storage` | bytes per service. `mail_used_storage` and `calendar_used_storage` equal the bytes of the user's `Mail` and `Calendar` folders exactly (mail: 48 of 50 users; one differs by its `.version_info` file, one by 150 159 bytes not explained). `drive_used_storage` is close to the sum of the `#SynoVersionRepo` version files, so each version is counted once. `contact_used_storage` is a little under the `Contact` folder (photos or `.version_info` not counted [I]) |
| `enable_drive`, `enable_mail`, `enable_contact`, `enable_calendar` | 1/0 |
| `root_folder_id` | the user's My Drive root id |
| `access_token` | OAuth token (secret) |
| `next_page_token` | Drive change-feed cursor |

`backup_status_table(user_id, <service>_service_folder_status)` (1 on
every user) and `removing_storage_table` (empty) are bookkeeping.

### 3.3 Run logs [F]

- `service-log.sqlite` `service_log_table`: one row per run
  (`task_execution_id`), user and service **that had something to do** —
  in continuous mode a run that finds no changes writes nothing, so a
  user's last row can be months old without anything being wrong.
  Columns: `execution_status`, `error_code`, `job_type`, `service_type`,
  `backup_policy`, `start_run_time`, `end_run_time`, `user_id`,
  `item_success_count`, `item_warning_count`, `item_error_count`,
  `transfered_size`.
  - `service_type`: 0 Drive, 1 mail, 2 contacts, 3 calendar.
  - `execution_status`: 1 succeeded; 5 failed (seen with `error_code` -2
    "Connection failure" and -120 "Invalid OAuth scopes"); 6 partly failed or
    cancelled (-1 "Task canceled", -32 "File is not supported" on calendar
    attachments, -63 "Server file cannot be found", -89 "The email address is
    invalid").
- `user-log.sqlite` `user_log_table`: the same per run and user, with one
  status, error code and transferred size per service in columns.
- `mail-log.sqlite`, `calendar-log.sqlite`, `contact-log.sqlite`,
  `file-log.sqlite` (Drive): `<service>_log_table(timestamp,
  task_execution_id, task_id, user_id, job_type, log_status,
  descript_string, error_code)` — the text the log page shows, e.g.
  `User [x]'s mail data was backed up (success: 8; error: 0; warning: 0).`

### 3.4 Per-user item databases [F]

Every item table records versions: one row per (item, version) with
`version_number`, `is_latest_version`, `start_time` (when this version was
backed up) and `end_time` (section 1).

| database | table | columns beyond the version ones |
|---|---|---|
| `mail.sqlite` | `mail_table` | `mail_id` (Gmail message id, 16 hex), `thread_id`, `sender`, `subject`, `snippet`, `has_attachments`, `remote_timestamp` |
| | `mail_label_table` | `mail_id`, `label_id` (with its own `is_latest_version`, `start_time`, `end_time`) |
| `mail-label.sqlite` | `mail_label_table` | `label_id`, `label_name`, `label_type` (0 system, user labels otherwise [I]), `forever` |
| `calendar.sqlite` | `calendar_table` | `calendar_id`, `calendar_name`, `calendar_type`, colours, `timezone`, `description` |
| | `event_change_table` | `calendar_id`, `sync_token`, `is_remote_deleted` |
| `calendar-event.sqlite` | `calendar_event_table` | `event_id`, `calendar_id`, `event_type`, `etag`, `recurring_event_id`, `organizer`, `summary`, `location`, `is_all_day`, `event_start_time`, `event_end_time` |
| `contact.sqlite` | `contact_table` | `contact_id` (`people/c…` or `otherContacts/c…`), `contact_etag`, names, `primary_email`, `photo_etag` |
| | `contact_group_table` | `contact_id`, `group_id` |
| `contact-group.sqlite` | `group_table` | `group_id` (`contactGroups/…`), `group_name`, `group_type`, `system_group_name` |

`mail.sqlite` `config_table` also holds `max_history_id`, Gmail's
history cursor. The `*-unfinished-event`, `*-cached` and `index-data`
databases are work queues, empty when the task is idle.

There is no Drive item database: Drive's state is the `MyDrive` tree, its
version repository and the LevelDB map (section 5).

## 4. Mail, calendar and contact items [F]

### 4.1 Item folders

- Mail: `Mail/<XX>/<YY>/<mail_id>/`.
- Calendar: the folder name is `base64(calendar_id) + "-" +
  base64(event_id)` (standard alphabet with `=` padding), cut into folders
  of 64 characters: `…/ZW4udXNhI2hvbGlkYXlAZ3JvdXAudi5jYWxlbmRhci5nb29nbGUuY29t-MjAzMTA/xMjBfZjUybWh1M2IyaDZxOTdzdmo5NzM0YTdtMW8=/`.
  Joining the segments gives the name back.
- Contact: `base64(contact_id)`, cut the same way.
- No item name in the task contained `/` or `+`, so how ABG would write a base64 `/` in a folder name is unknown [?]. Joining the 64-character segments with nothing matched every calendar event and contact.

### 4.2 Fragments

Each folder holds the fragments of each version, named
`v<version>-<k>-<part>`, where `k` counts from 1 in the order of the META's
`content_list`, and the META itself comes last:

| part | content |
|---|---|
| `SKEL` | the RFC 822 message as Gmail returned it with each attachment's body removed: the MIME part keeps its headers and gains `X-ABL-ID: <fragment_id>`, its body is empty |
| `ATT_<n>` | attachment n, decoded (the PNG, PDF, ... itself) |
| `INL_<n>` | an inline part (an image referenced by `Content-ID`, ...) [I]; one message had 148 |
| `MSG_<n>` | an attached message (`message/rfc822`) [I] |
| `DLA_<n>` | seen once; meaning unknown [?] |
| `PHOTO` | a contact's photo; it comes **after** the contact's `META` (`v1-1-META`, `v1-2-PHOTO`) |
| `META` | JSON, below; last in a message's or event's fragment list |

A message with no attachments is `v1-1-SKEL`, `v1-2-META`; with one,
`v1-1-SKEL`, `v1-2-ATT_0`, `v1-3-META`. Calendar events are `v1-1-META`
(two events had `ATT_0`, `ATT_1`), contacts `v1-1-META` and maybe
`v1-2-PHOTO`. Across the 704 k item versions examined, numbering always
ran 1..n without gaps; it put `META` last except on contacts with a
photo [F].

A few folders also hold `.version_info` (4 seen: one message with 149
fragments, three contacts of 58-59 KB): JSON `{".v1": {"content_bundle":
["v1-1-SKEL", "v1-2-INL_0", ...]}}`, the fragment list per version [F].
Why only these four have one is unknown [?].

### 4.3 Mail META (`"version": "2.0"`)

```
{ "bcc": [], "cc": [], "to": [{"email", "name"}], "from": {"email", "name"},
  "subject": "...", "has_attachment": false, "remote_timestamp": <unix s>,
  "client_metadata": { Gmail's users.messages resource, format=metadata:
      "id", "threadId", "historyId", "internalDate" (ms), "labelIds": [...],
      "payload": {"headers": [{"name", "value"}], "mimeType"},
      "sizeEstimate", "snippet" },
  "content_list": [
      {"fragment_id": "ID-skel", "path_postfix": "SKEL", "type": 0, "content_id": "", "file_name": ""},
      {"fragment_id": "ID-file", "path_postfix": "ATT_0", "type": 4,
       "file_name": "icon.png", "content_id": "icon.png", "size": 3910,
       "hash": "<MD5 of the ATT file, lower-case hex>"} ],
  "version": "2.0" }
```

`hash` is the MD5 of the `ATT_<n>` file as stored (checked on every
attachment, see section 8) [F]. `has_attachment` is false for inline
images even when they have an `ATT` fragment [F].

**Rebuilding the message**: read `SKEL`; for each part carrying `X-ABL-ID:
<fragment_id>`, find the `content_list` entry with that `fragment_id`,
re-encode the `ATT_<n>` bytes with the part's `Content-Transfer-Encoding`
(base64 in every case seen) and put them as the part's body, dropping the
`X-ABL-ID` header [I: the structure is clear; byte-exact equality with the
Gmail original was not tested].

### 4.4 Calendar and contact META (`"version": "1.0"`)

- Calendar: `{"attachment_list": [...], "client_metadata": <the Calendar
  API events resource: id, iCalUID, summary, start, end, organizer,
  creator, status, ...>, "version": "1.0"}`.
- Contact: `{"client_metadata": <the People API person resource:
  emailAddresses, names, metadata.sources, ...>, "version": "1.0"}`.

## 5. Drive [F]

### 5.1 `MyDrive/<path>`

The latest version of every file, as a normal file under its Drive name
and folder path, with Google formats converted as in the specification
[S]. This is the only part of the task a person can use without ABG.

### 5.2 `MyDrive/#SynoVersionRepo/<path>/#SynoVersions/`

One folder per Drive file (by its path), holding:

- `GMT-<yyyy.mm.dd-hh.mm.ss>-v<n>`: the whole file as it was in version n,
  the time being when ABG backed it up, in UTC.
- `GMT-<…>-v<n>.metadata`: JSON `{"client_metadata": <Drive API v2 files
  resource: id, fileSize, md5Checksum, mimeType, createdDate, modifiedDate
  (Unix s), labels {starred, trashed}, permissions [...], ...>, "hash":
  "<MD5 of the version file>", "is_dir": false, "size": "<bytes, as a
  string>", "version": "1.0"}`.
- `cached_info`: JSON `{"latest_version": {"id", "time", "type"},
  "oldest_version": {...}, "second_oldest_version": {...}, "version_count",
  "version": "1.0"}`.

The latest version has the same content as `MyDrive/<path>` (same size and
MD5 seen) [F]. On Btrfs the copies share blocks [S, I], so the version
repository costs much less disk space than its listed size. A file deleted
in Google keeps its `#SynoVersionRepo` folder; its `MyDrive` copy goes
[F].

### 5.3 `MyDrive/#SynoRepo/id-path-mapping.db/`

A LevelDB (`CURRENT`, `MANIFEST-*`, `*.ldb`, `*.log`). Keys are Drive file
ids, values JSON `{"infoPair": [{"name": "<file name>", "parentId": "<parent
id>"}]}`; a key with a `#DEL` suffix marks a deleted item [F, from the raw
`.ldb` strings]. With it the Drive tree can be rebuilt by id.

## 6. `single-instancing.db/` [F]

LevelDB. Keys are `<size>|<MD5>`; values JSON `{"path_infos": [{"id":
"<user id>", "path": "<XX>/<YY>/<item>/v<ver>-<k>-ATT_<n>", "service_type":
<n>}, ...]}`: every place one attachment's content is kept. Seen with
`enable_dedup = 0`. Its `service_type` is not the run log's (an
attachment under `Mail/` had 2) [?]. Every path is still a file of its own
in the listing; on Btrfs the copies share blocks [I].

## 7. Reading a task

1. `task-config.sqlite` for the domain; `account.sqlite` for the users and
   their folders.
2. Per user, the item databases list every version; the item folder is
   found by name (4.1) and its `META` names the fragments (4.2).
3. Drive: walk `MyDrive` for the latest files; walk `#SynoVersionRepo`
   for history, including deleted files.
4. To show "the mailbox at time T": the rows with `start_time <= T <
   end_time`.

## 8. Findings in the task examined [F]

- Every message, event and contact version in the 50 users' databases has
  its folder, its `META` and (messages) its `SKEL`; no item folder is
  missing from the databases; every `MyDrive` file has a version history
  whose latest version has its size. (Checked against a full listing of
  1.43 M files, then by filecat's own summary in 21 s.)
- The task was live: 7 items in the databases were backed up after the
  listing was taken. A summary made at the end of a long walk always sees
  some; filecat counts them separately.
- One user (account status -2) was deleted from the domain: every run
  since 2025-12-01 fails with "The email address is invalid", and the
  services are disabled. ABG keeps the data (949 KB).
- Windows: 3 854 folders under `Calendar` (and 7 under `MyDrive`) are past
  MAX_PATH (260 characters) when reached as
  `\\server\share\ActiveBackupForGoogleWorkspace\task_1\...`; the
  longest event folders are cut into four 64-character segments. Without
  `LongPathsEnabled`, Python cannot open them unless the path carries the
  `\\?\UNC\` prefix.
- `--verify-backups` over the whole task: 706 545 `META` and `.metadata` files read, and every attachment and Drive version they name present with its size and MD5. None failed. It took 27 minutes over SMB.

## 9. Paths, copies and moves

### 9.1 Everything inside a task is relative [F]

Nothing in the task records where it lives, so a copied `task_<n>` folder
is still fully readable, and filecat recognises it anywhere (detection
looks at the folder's contents, not its location):

- `account.sqlite` stores each user's folder as a bare name
  (`user_repo_name`, e.g. `jdoe@example.org`), relative to `task_<n>`.
- Mail, calendar and contact folders have no stored path at all: their
  names come from the item's id (the Gmail message id, or base64 of the
  calendar, event or contact id), under bucket folders a reader finds by
  listing (2).
- Drive files are found by their path under `MyDrive/`; `#SynoRepo` maps ids
  to names and parent ids, not to paths on the NAS (5.3).
- `single-instancing.db` stores paths such as `A8/6C/<mail id>/v1-2-ATT_0`
  plus a user id, relative to the user's service folder (6).
- `task-config.sqlite` has the domain, admin and policy, but no volume or
  share path.
- Searched for absolute paths (`/volume…`, `\\server\…`, `X:\…`, the share
  and task folder names): every `.sqlite` of the task and of all 50 users,
  and the `LOG`, `LOG.old`, `MANIFEST-*` and `CURRENT` files of both
  LevelDBs. The only hits were inside email snippets in `mail.sqlite`. The
  LevelDB logs hold only record numbers and keys. The `.ldb` tables were
  read as raw strings only; the Lucene search indexes were not searched.

The same holds for the parts of an ABB PC backup (`@ActiveBackup`) that
filecat reads; the rest of its `@data` was not searched. For contrast,
Veeam's `.vbm` does record the original absolute write location
(`DirPath`), which is why a moved Veeam job can be recognised from inside.

### 9.2 Telling a copy or a move from the original [I]

There is no "I was moved" flag; these are the signals:

- **Copies share a key.** Two folders holding the same task have the same
  task id, creation time and admin id in `task-config.sqlite`; filecat
  uses `abg-task:<admin id>:<task id>:<created>` as the copy key, so
  `filecat backups` lists them under "Copies".
- **The live one keeps running.** A continuous task writes to
  `service-log.sqlite` and the per-user databases about every 10 minutes
  (and the LevelDB `LOG` files are rewritten on every run), so the live
  store's latest run time is close to now; a copy stops at the moment it
  was made.
- **File times against the databases** (not implemented): each version's
  `start_time` is when ABG backed it up, and its fragment files were
  written within seconds of it. Files whose modification times are all
  later than their `start_time`, or clustered at one moment, were copied
  by a tool that did not keep times.
- **Location** (weak): the original sits at
  `<share>/ActiveBackupForGoogleWorkspace/task_<n>` beside `@ActiveBackup`.
  Anywhere else suggests a copy, but since the location is not recorded
  inside the task, it proves nothing.
- **Disk usage** (not visible over SMB): on Btrfs, single-instanced
  attachments and Drive versions share blocks with each other. A copy to
  another volume loses that sharing and takes more space for the same
  listing.

## 10. Checking a task, cheapest first

1. The databases against a listing of the task (what filecat does by
   default): every item version has its folder and `META` (and a message
   its `SKEL`); no item folders the databases don't know; every `MyDrive`
   file has a version history whose latest version has its size; each
   active user's latest run per service succeeded.
2. Read every `META` and `.metadata` (`--verify-backups`): every fragment
   and version they name exists with that size and MD5.
3. Rebuild messages from SKEL and ATT and compare `sizeEstimate`, or
   compare Drive versions with `client_metadata.md5Checksum` (Drive's own
   MD5; not usable for converted Google formats) [I].

## 11. Not known yet

- The bucket hash (2).
- Where shared drives go (2).
- The meaning of `backup_policy`, `retention_policy` and `label_type`
  values other than those seen.
- Encrypted destinations (names cut at 143 characters [S]).
- Whether `single-instancing.db`'s `service_type` codes match anything else.

## 12. Microsoft 365

`ActiveBackupForMicrosoft365/task_<n>/` on the same share has the same
shape: `@ActiveBackupOffice365-Databases/` (with `group`, `site`, `teams`
databases besides the per-user ones), user folders with `Mail`,
`Archive-Mail`, `Calendar`, `Contact` and `OneDrive`, plus `Groups/` and
`Sites/` [F, from the folder listing only]. It was not examined further.
