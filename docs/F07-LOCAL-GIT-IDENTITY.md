# P01-12B.1 — локальное применение F07, вариант Б

GitHub account metadata для `Good-Eli/fixlevelup` подтверждает owner `Good-Eli`, numeric ID `61868766`. Для будущих Git commits используй ID-based noreply:

```text
61868766+Good-Eli@users.noreply.github.com
```

В PowerShell из каталога локального клона после проверки, что активен именно репозиторий FixLevelUp:

```powershell
git remote -v
git status --short --branch

git config --local --replace-all user.email "61868766+Good-Eli@users.noreply.github.com"

git config --local --get user.email
git var GIT_AUTHOR_IDENT
git var GIT_COMMITTER_IDENT
```

Проверить в выводе обеих команд `git var`, что email стал noreply. Если `GIT_AUTHOR_EMAIL` или `GIT_COMMITTER_EMAIL` задан в окружении, он может переопределить конфигурацию; не печатай неизвестные значения в публичный отчёт. Не меняй `user.name`, global/system config, remote или branch.

Дополнительно в GitHub Settings → Emails включи **Keep my email addresses private** и проверь, что noreply email доступен/разрешён для аккаунта. Агент не изменяет Git identity и настройки аккаунта без отдельного разрешения владельца по [AGENTS](../AGENTS.md), поэтому эти действия выполняет владелец.

**Историческое ограничение:** изменение локального `user.email` действует только на будущие commits. Оно не меняет уже опубликованные Author/Committer поля. Текущая публичная история содержит прежнюю non-noreply identity; значение старого адреса намеренно не воспроизводится. Переписывание истории и force push не выполнялись и не рекомендуются в рамках P01-12B.1.
