PLUGIN_NAME=            client-control
_PLUGIN_DEVEL=
PLUGIN_DIR=             security/client-control
PLUGIN_VERSION=         1.0
PLUGIN_COMMENT=         Per-client access and speed control
PLUGIN_MAINTAINER=      admin@volgodon.ru
PLUGIN_WWW=             https://github.com/Omnividente/opnsense-client-control

PLUGINSDIR?=            ${.CURDIR}/.build/opnsense-plugins

.include "${PLUGINSDIR}/Mk/plugins.mk"
