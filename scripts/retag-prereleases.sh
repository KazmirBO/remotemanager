#!/usr/bin/env bash
# Jednorazowe przenumerowanie wydań wstępnych z 0.1.x na 0.0.x: tag, tytuł, opis i nazwy plików
# wydania. Uruchamia je workflow "przenumerowanie" (.github/workflows/retag.yml) z gałęzi main.
# Wymaga gh z prawem zapisu do repozytorium (GH_TOKEN, GH_REPO) i katalogu roboczego z CHANGELOG.md,
# w którym sekcje dawnych wydań mają już nowe numery.
#
#   scripts/retag-prereleases.sh            tylko sprawdza stan i wypisuje plan
#   scripts/retag-prereleases.sh wykonaj    wprowadza zmiany
#
# Skrypt można uruchamiać wielokrotnie: pomija to, co już zrobione. Stary tag usuwa na końcu i tylko
# wtedy, gdy wydanie wskazuje już nowy tag, więc przerwany przebieg niczego nie gubi.
set -euo pipefail

mode="${1:-plan}"
: "${GH_REPO:?brak GH_REPO}"

# Ostatnia cyfra wersji i commit, na który wskazywał dawny tag v0.1.<cyfra>. Tag o tej nazwie na
# innym commicie to już nie dawne wydanie wstępne (np. zwykłe wydanie 0.1.0) i skrypt go nie rusza.
versions=(
  "0 a91eadb1ec70c4a9d69c48dcdb9c30070cc44c8b"
  "1 e1af45483c196f478ec97b130c1ca6a59c9180ae"
  "2 a520c888376cdd0961eb23417bab69c6518b0520"
  "3 d7bc8f43de30f7bf221f2e1c6bc2c28934425ed0"
  "4 52c4e29f630b1482b4efda719b78b2c6aceebf98"
  "5 cb5a8030ab30149f0ced3d043c6ec0a9111142bd"
)

# Wykonuje zmianę albo, w trybie planu, tylko ją wypisuje.
change() {
  local what="$1"
  shift
  if [ "$mode" = "wykonaj" ]; then
    echo "  wykonuję: $what"
    "$@" > /dev/null
  else
    echo "  plan: $what"
  fi
}

# Commit, na który wskazuje tag, albo pusty tekst, gdy tagu nie ma.
tag_sha() {
  gh api "repos/$GH_REPO/git/matching-refs/tags/$1" \
    --jq ".[] | select(.ref == \"refs/tags/$1\") | .object.sha"
}

# Identyfikator wydania przypiętego do tagu ("<id> <czy wstępne>") albo pusty tekst.
release_of() {
  gh api "repos/$GH_REPO/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"$1\") | \"\(.id) \(.prerelease)\""
}

for entry in "${versions[@]}"; do
  read -r x sha <<< "$entry"
  old="v0.1.$x"
  new="v0.0.$x"
  echo "$old -> $new"

  # 1. Nowy tag na tym samym commicie.
  new_sha="$(tag_sha "$new")"
  if [ -z "$new_sha" ]; then
    change "tag $new na commicie $sha" \
      gh api "repos/$GH_REPO/git/refs" -f "ref=refs/tags/$new" -f "sha=$sha"
  elif [ "$new_sha" != "$sha" ]; then
    echo "  błąd: tag $new istnieje i wskazuje inny commit ($new_sha)" >&2
    exit 1
  else
    echo "  tag $new już istnieje"
  fi

  # 2. Wydanie: nowy tag, tytuł i opis z sekcji CHANGELOG.md (tak samo jak workflow "wydanie").
  id=""
  found="$(release_of "$old")"
  read -r old_id old_pre <<< "$found"
  if [ -n "$old_id" ] && [ "$old_pre" = "true" ]; then
    id="$old_id"
    awk -v v="0.0.$x" 'index($0, "## " v) == 1 { p = 1; next } /^## / { p = 0 } p' CHANGELOG.md > notes.md
    if ! grep -q '[^[:space:]]' notes.md; then
      echo "  błąd: brak sekcji 0.0.$x w CHANGELOG.md" >&2
      exit 1
    fi
    change "wydanie $id: tag $new, tytuł \"Menedżer sesji 0.0.$x\", opis z CHANGELOG.md" \
      gh api -X PATCH "repos/$GH_REPO/releases/$id" \
      -f "tag_name=$new" -f "name=Menedżer sesji 0.0.$x" -F "body=@notes.md"
  else
    found="$(release_of "$new")"
    read -r id _ <<< "$found"
    if [ -z "$id" ]; then
      echo "  błąd: nie ma wydania wstępnego dla $old ani wydania dla $new" >&2
      exit 1
    fi
    echo "  wydanie $id już wskazuje $new"
  fi

  # 3. Nazwy plików wydania.
  assets="$(gh api "repos/$GH_REPO/releases/$id/assets?per_page=100" --jq '.[] | "\(.id) \(.name)"')"
  while read -r asset_id name; do
    [ -n "$asset_id" ] || continue
    renamed="${name//_0.1.${x}_/_0.0.${x}_}"
    if [ "$renamed" != "$name" ]; then
      change "plik $name -> $renamed" \
        gh api -X PATCH "repos/$GH_REPO/releases/assets/$asset_id" -f "name=$renamed"
    else
      echo "  plik $name bez zmian"
    fi
  done <<< "$assets"

  # 4. Stary tag: usuwany tylko wtedy, gdy nadal wskazuje dawny commit, a wydanie jest już przy
  #    nowym tagu (w trybie planu tego drugiego jeszcze nie ma, więc sama zapowiedź).
  old_sha="$(tag_sha "$old")"
  if [ -z "$old_sha" ]; then
    echo "  tagu $old już nie ma"
  elif [ "$old_sha" != "$sha" ]; then
    echo "  tag $old wskazuje inny commit ($old_sha), zostaje"
  elif [ "$mode" = "wykonaj" ]; then
    moved="$(gh api "repos/$GH_REPO/releases/$id" --jq .tag_name)"
    if [ "$moved" != "$new" ]; then
      echo "  błąd: wydanie $id nadal wskazuje $moved, tag $old zostaje" >&2
      exit 1
    fi
    change "usunięcie tagu $old" gh api -X DELETE "repos/$GH_REPO/git/refs/tags/$old"
  else
    echo "  plan: usunięcie tagu $old"
  fi
done

rm -f notes.md
echo "Gotowe (tryb: $mode)."
