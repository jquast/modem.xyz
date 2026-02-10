/*
 * ansi2png.c -- render ANSI art to PNG using libansilove.
 *
 * Usage: ansi2png INPUT OUTPUT.png
 *
 * Environment variables:
 *   ANSILOVE_FONT       font name (e.g. CP437, TOPAZ), default CP437
 *   ANSILOVE_SCALE      scale factor (integer, default 1)
 *   ANSILOVE_BITS        bits mode (8 or 9)
 *   ANSILOVE_COLUMNS    column count (integer)
 *   ANSILOVE_MODE       rendering mode (ced, transparent, workbench)
 *   ANSILOVE_ICECOLORS  set to "1" to enable iCE colors
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ansilove.h>

struct font_entry {
	const char *name;
	uint8_t     value;
};

static const struct font_entry font_map[] = {
	{ "CP437",            ANSILOVE_FONT_CP437 },
	{ "CP437_80x50",      ANSILOVE_FONT_CP437_80x50 },
	{ "CP737",            ANSILOVE_FONT_CP737 },
	{ "CP775",            ANSILOVE_FONT_CP775 },
	{ "CP850",            ANSILOVE_FONT_CP850 },
	{ "CP852",            ANSILOVE_FONT_CP852 },
	{ "CP855",            ANSILOVE_FONT_CP855 },
	{ "CP857",            ANSILOVE_FONT_CP857 },
	{ "CP860",            ANSILOVE_FONT_CP860 },
	{ "CP861",            ANSILOVE_FONT_CP861 },
	{ "CP862",            ANSILOVE_FONT_CP862 },
	{ "CP863",            ANSILOVE_FONT_CP863 },
	{ "CP865",            ANSILOVE_FONT_CP865 },
	{ "CP866",            ANSILOVE_FONT_CP866 },
	{ "CP869",            ANSILOVE_FONT_CP869 },
	{ "TERMINUS",         ANSILOVE_FONT_TERMINUS },
	{ "SPLEEN",           ANSILOVE_FONT_SPLEEN },
	{ "MICROKNIGHT",      ANSILOVE_FONT_MICROKNIGHT },
	{ "MICROKNIGHT_PLUS", ANSILOVE_FONT_MICROKNIGHT_PLUS },
	{ "MOSOUL",           ANSILOVE_FONT_MOSOUL },
	{ "POT_NOODLE",       ANSILOVE_FONT_POT_NOODLE },
	{ "TOPAZ",            ANSILOVE_FONT_TOPAZ },
	{ "TOPAZ_PLUS",       ANSILOVE_FONT_TOPAZ_PLUS },
	{ "TOPAZ500",         ANSILOVE_FONT_TOPAZ500 },
	{ "TOPAZ500_PLUS",    ANSILOVE_FONT_TOPAZ500_PLUS },
	{ NULL, 0 }
};

static uint8_t
lookup_font(const char *name)
{
	if (name == NULL)
		return ANSILOVE_FONT_CP437;

	for (size_t i = 0; font_map[i].name != NULL; i++) {
		if (strcasecmp(name, font_map[i].name) == 0)
			return font_map[i].value;
	}

	fprintf(stderr, "ansi2png: unknown font '%s', "
	    "using CP437\n", name);
	return ANSILOVE_FONT_CP437;
}

int
main(int argc, char *argv[])
{
	struct ansilove_ctx ctx;
	struct ansilove_options options;
	const char *val;

	if (argc != 3) {
		fprintf(stderr, "usage: ansi2png INPUT OUTPUT.png\n");
		return 1;
	}

	if (ansilove_init(&ctx, &options) == -1) {
		fprintf(stderr, "ansi2png: init failed\n");
		return 1;
	}

	options.font = lookup_font(getenv("ANSILOVE_FONT"));

	val = getenv("ANSILOVE_SCALE");
	if (val)
		options.scale_factor = (uint8_t)atoi(val);

	val = getenv("ANSILOVE_BITS");
	if (val)
		options.bits = (uint8_t)atoi(val);

	val = getenv("ANSILOVE_COLUMNS");
	if (val)
		options.columns = (int16_t)atoi(val);

	val = getenv("ANSILOVE_MODE");
	if (val) {
		if (strcasecmp(val, "ced") == 0)
			options.mode = ANSILOVE_MODE_CED;
		else if (strcasecmp(val, "transparent") == 0)
			options.mode = ANSILOVE_MODE_TRANSPARENT;
		else if (strcasecmp(val, "workbench") == 0)
			options.mode = ANSILOVE_MODE_WORKBENCH;
	}

	val = getenv("ANSILOVE_ICECOLORS");
	if (val && strcmp(val, "1") == 0)
		options.icecolors = true;

	if (ansilove_loadfile(&ctx, argv[1]) == -1) {
		fprintf(stderr, "ansi2png: load failed: %s\n",
		    ansilove_error(&ctx));
		ansilove_clean(&ctx);
		return 1;
	}

	if (ansilove_ansi(&ctx, &options) == -1) {
		fprintf(stderr, "ansi2png: render failed: %s\n",
		    ansilove_error(&ctx));
		ansilove_clean(&ctx);
		return 1;
	}

	if (ansilove_savefile(&ctx, argv[2]) == -1) {
		fprintf(stderr, "ansi2png: save failed: %s\n",
		    ansilove_error(&ctx));
		ansilove_clean(&ctx);
		return 1;
	}

	ansilove_clean(&ctx);
	return 0;
}
