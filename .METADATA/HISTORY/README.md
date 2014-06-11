# This ./.METADATA/HISTORY/ directory provides a simple way to express a history timeline view of
# the evolution of a project or projects over time.
#
# Each release of a project's source-code should be represented by a single file in this directory.
#
# Each file should be named based on the date of publication or copyright of the related project's
# version combined with the project name and version. E.g:
#
# YYYY-MM-DD-PROJECT-VERSION
# 1998-01-08-libbf-0.8.2b    (libbf v0.8.2b released 8th January 1998)
#
# A project branch that is the result of merging other branches containing different projects and/or
# versions will therefore automatically inherit a date-ordered history that is  machine-readable
# and gives an immediate understanding of the project timeline.
#
# Each file should be treated as a shell script (sh/dash) that defines variables and conforms to
# shell rules for variable names and expansion. Files can be included in other shell scripts
# using  '. $FILENAME' for analysis and reporting, e.g:
#
# for H in ./METADATA/HISTORY/; do
#  unset -v URL URL_SRC URL_ARCHIVE DATE_RETRIEVED WHO_RETRIEVED
#  . $H
#  echo -n "$(basename $H), $PROJECT"
#  [ ! -z "$RETRIEVED_DATE" ] && echo -n ", retrieved $RETRIEVED_DATE"
#  [ ! -z "$RETRIEVED_BY"   ] && echo -n " by $RETRIEVED_BY"
#  [ ! -z "$URL_SRC"        ] && echo -n " from $URL_SRC"
#  echo
# done
#
#
# The file should only contain KEY=VALUE entries or comment lines (starting with #).
#
# Common KEY names are:
#
# PROJECT="name of project"
# URL_SRC="where the project source-code was (can-be) retrieved from"
# URL="the project's 'home page' (even if no longer operational)"
# URL_ARCHIVE="a cached copy of the project's 'home page' (such as at http://archive.org)"
# RELEASE_DATE="YYYY-MM-DD date source-code was originally published, copyrighted, or otherwise attributed"
# RETRIEVED_DATE="YYYY-MM-DD date source-code was retrieved from URL_SRC"
# RETRIEVED_BY="Name <email@address>"
META_HISTORY_VERSION="1"

