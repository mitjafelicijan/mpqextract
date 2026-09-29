#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "miniz.h"

#define MPQ_SIGNATURE 0x1A51504D

#define MPQ_HASH_ENTRY_EMPTY 0xFFFFFFFF
#define MPQ_HASH_ENTRY_DELETED 0xFFFFFFFE

#define MPQ_FILE_IMPLODE 0x00000100
#define MPQ_FILE_COMPRESS 0x00000200
#define MPQ_FILE_ENCRYPTED 0x00010000
#define MPQ_FILE_FIX_KEY 0x00020000
#define MPQ_FILE_SINGLE_UNIT 0x01000000
#define MPQ_FILE_EXISTS 0x80000000

#define MPQ_COMPRESSION_HUFFMANN 0x01
#define MPQ_COMPRESSION_ZLIB 0x02
#define MPQ_COMPRESSION_PKWARE 0x08
#define MPQ_COMPRESSION_BZIP2 0x10
#define MPQ_COMPRESSION_SPARSE 0x20
#define MPQ_COMPRESSION_ADPCM_M 0x40
#define MPQ_COMPRESSION_ADPCM_S 0x80

enum {
	MPQ_HASH_TABLE_OFFSET = 0,
	MPQ_HASH_NAME_A = 1,
	MPQ_HASH_NAME_B = 2,
	MPQ_HASH_FILE_KEY = 3
};

#pragma pack(push, 1)

typedef struct {
  uint32_t signature;
  uint32_t header_size;
  uint32_t archive_size;
  uint16_t format_version;
  uint16_t sector_size_shift;
  uint32_t hash_table_offset;
  uint32_t block_table_offset;
  uint32_t hash_table_entries;
  uint32_t block_table_entries;
} MPQHeader;

typedef struct {
  uint32_t hash_a;
  uint32_t hash_b;
  uint16_t locale;
  uint16_t platform;
  uint32_t block_index;
} MPQHashEntry;

typedef struct {
  uint32_t file_offset;
  uint32_t compressed_size;
  uint32_t file_size;
  uint32_t flags;
} MPQBlockEntry;

#pragma pack(pop)

static uint32_t crypt_table[0x500];

// MPQ cryptography

static void mpq_init_crypt_table(void) {
	uint32_t seed = 0x00100001;

	for (uint32_t i = 0; i < 0x100; i++) {
		for (uint32_t j = i, n = 0; n < 5; n++, j += 0x100) {
			seed = (seed * 125 + 3) % 0x2AAAAB;
			uint32_t temp1 = (seed & 0xFFFF) << 16;

			seed = (seed * 125 + 3) % 0x2AAAAB;
			uint32_t temp2 = seed & 0xFFFF;

			crypt_table[j] = temp1 | temp2;
		}
	}
}

static uint32_t mpq_hash_string(const char *str, uint32_t hash_type) {
	uint32_t seed1 = 0x7FED7FED;
	uint32_t seed2 = 0xEEEEEEEE;

	while (*str) {
		unsigned char ch = (unsigned char)toupper((unsigned char)*str++);
		seed1 = crypt_table[(hash_type << 8) + ch] ^ (seed1 + seed2);
		seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;
	}

	return seed1;
}

static void mpq_decrypt(void *data, size_t size, uint32_t key) {
	uint32_t seed = 0xEEEEEEEE;
	uint32_t *words = data;

	size_t count = size / sizeof(uint32_t);

	for (size_t i = 0; i < count; i++) {
		seed += crypt_table[0x400 + (key & 0xFF)];

		uint32_t encrypted = words[i];
		uint32_t decrypted = encrypted ^ (key + seed);

		words[i] = decrypted;
		seed = decrypted + seed + (seed << 5) + 3;
		key = ((~key << 21) + 0x11111111) | (key >> 11);
	}
}

// Tables

static void *read_table(FILE *fp, uint32_t offset, uint32_t entries, size_t entry_size, uint32_t key) {
	if (entries != 0 && entry_size > SIZE_MAX / entries) {
		fprintf(stderr, "table size overflow\n");
		return NULL;
	}

	size_t size = (size_t)entries * entry_size;

	if (fseek(fp, (long)offset, SEEK_SET) != 0) {
		perror("fseek");
		return NULL;
	}

	void *table = malloc(size);

	if (!table) {
		perror("malloc");
		return NULL;
	}

	if (fread(table, 1, size, fp) != size) {
		fprintf(stderr, "failed to read MPQ table\n");
		free(table);
		return NULL;
	}

	mpq_decrypt(table, size, key);

	return table;
}

// Hash table lookup

static MPQHashEntry *find_file(MPQHashEntry *table, uint32_t table_size, const char *filename) {
	if (table_size == 0) {
		return NULL;
	}

	uint32_t offset_hash = mpq_hash_string(filename, MPQ_HASH_TABLE_OFFSET);
	uint32_t hash_a = mpq_hash_string(filename, MPQ_HASH_NAME_A);
	uint32_t hash_b = mpq_hash_string(filename, MPQ_HASH_NAME_B);

	uint32_t start = offset_hash % table_size;

	for (uint32_t i = 0; i < table_size; i++) {
		uint32_t index = (start + i) % table_size;

		MPQHashEntry *entry = &table[index];

		if (entry->block_index == MPQ_HASH_ENTRY_EMPTY) {
			return NULL;
		}

		if (entry->block_index == MPQ_HASH_ENTRY_DELETED) {
			continue;
		}

		if (entry->hash_a == hash_a && entry->hash_b == hash_b) {
			return entry;
		}
	}

	return NULL;
}

/* =========================================================
 * Compression
 * ========================================================= */

static int decompress_sector(const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size) {
	// MPQ stores a sector uncompressed when compression would not make it smaller.
	if (input_size >= output_size) {
		memcpy(output, input, output_size);
		return 0;
	}

	if (input_size < 1) {
		fprintf(stderr, "invalid compressed sector\n");
		return -1;
	}

	uint8_t compression = input[0];

	input++;
	input_size--;

	if (compression != MPQ_COMPRESSION_ZLIB) {
		fprintf(stderr, "unsupported compression type: 0x%02X\n", compression);
		return -1;
	}

	uLongf dest_size = (uLongf)output_size;

	int result = uncompress(output, &dest_size, input, (uLong)input_size);

	if (result != Z_OK) {
		fprintf(stderr, "zlib decompression failed: %d\n", result);
		return -1;
	}

	if (dest_size != output_size) {
		fprintf(stderr, "decompressed size mismatch: %lu != %zu\n", (unsigned long)dest_size, output_size);
		return -1;
	}

	return 0;
}

static void *mpq_read_file(FILE *fp, const MPQHeader *header, MPQHashEntry *hash_table, MPQBlockEntry *block_table, const char *filename, size_t *result_size) {
	*result_size = 0;

	MPQHashEntry *hash = find_file(hash_table, header->hash_table_entries, filename);

	if (!hash) {
		return NULL;
	}

	if (hash->block_index >= header->block_table_entries) {
		fprintf(stderr, "invalid block index for %s\n", filename);
		return NULL;
	}

	MPQBlockEntry *block = &block_table[hash->block_index];

	if (!(block->flags & MPQ_FILE_EXISTS)) {
		return NULL;
	}

	if (block->flags & MPQ_FILE_ENCRYPTED) {
		fprintf(stderr, "encrypted file unsupported: %s\n", filename);
		return NULL;
	}

	if (block->flags & MPQ_FILE_IMPLODE) {
		fprintf(stderr, "PKWARE implode unsupported: %s\n", filename);
		return NULL;
	}

	// Empty file
	if (block->file_size == 0) {
		void *data = malloc(1);

		if (!data) {
			return NULL;
		}

		*result_size = 0;

		return data;
	}

	// Single-unit file
	if (block->flags & MPQ_FILE_SINGLE_UNIT) {
		uint8_t *stored = malloc(block->compressed_size);
		uint8_t *output = malloc(block->file_size);

		if (!stored || !output) {
			free(stored);
			free(output);
			return NULL;
		}

		if (fseek(fp, (long)block->file_offset, SEEK_SET) != 0) {
			perror("fseek");

			free(stored);
			free(output);

			return NULL;
		}

		if (fread(stored, 1, block->compressed_size, fp) != block->compressed_size) {
			fprintf(stderr, "failed reading %s\n", filename);

			free(stored);
			free(output);

			return NULL;
		}

		if (block->flags & MPQ_FILE_COMPRESS) {
			if (decompress_sector(stored, block->compressed_size, output, block->file_size) != 0) {
				free(stored);
				free(output);

				return NULL;
			}
		} else {
			if (block->compressed_size < block->file_size) {
				fprintf(stderr, "invalid stored size for %s\n", filename);

				free(stored);
				free(output);

				return NULL;
			}

			memcpy(output, stored, block->file_size);
		}

		free(stored);
		*result_size = block->file_size;

		return output;
	}

	// Normal sector-based file

	uint32_t sector_size = 512u << header->sector_size_shift;
	uint32_t sector_count = (block->file_size + sector_size - 1) / sector_size;

	// If the file isn't compressed, there is no sector offset table to worry about.
	if (!(block->flags & MPQ_FILE_COMPRESS)) {
		uint8_t *output = malloc(block->file_size);

		if (!output) {
			return NULL;
		}

		if (fseek(fp, (long)block->file_offset, SEEK_SET) != 0) {
			perror("fseek");
			free(output);
			return NULL;
		}

		if (fread(output, 1, block->file_size, fp) != block->file_size) {
			fprintf(stderr, "failed reading %s\n", filename);
			free(output);
			return NULL;
		}

		*result_size = block->file_size;

		return output;
	}

	// Compressed sector-based file:
	// 
	//   uint32 offsets[sector_count + 1]
	//   sector 0
	//   sector 1
	//   ...

	uint32_t offset_count = sector_count + 1;
	size_t offset_table_size = (size_t)offset_count * sizeof(uint32_t);
	uint32_t *offsets = malloc(offset_table_size);

	if (!offsets) {
		return NULL;
	}

	if (fseek(fp, (long)block->file_offset, SEEK_SET) != 0) {
		perror("fseek");
		free(offsets);
		return NULL;
	}

	if (fread(offsets, sizeof(uint32_t), offset_count, fp) != offset_count) {
		fprintf(stderr, "failed reading sector table: %s\n", filename);
		free(offsets);
		return NULL;
	}

	// Validate sector table.
	if (offsets[0] < offset_table_size || offsets[0] > block->compressed_size) {
		fprintf(stderr, "invalid sector table: %s\n", filename);
		free(offsets);
		return NULL;
	}

	uint8_t *output = malloc(block->file_size);

	if (!output) {
		free(offsets);
		return NULL;
	}

	size_t output_position = 0;

	for (uint32_t i = 0; i < sector_count; i++) {
		uint32_t start = offsets[i];
		uint32_t end = offsets[i + 1];

		if (end < start || end > block->compressed_size) {
			fprintf(stderr, "invalid sector offsets: %s\n", filename);
			free(output);
			free(offsets);
			return NULL;
		}

		size_t stored_size = (size_t)(end - start);
		size_t expected_size = sector_size;
		size_t remaining = block->file_size - output_position;

		if (expected_size > remaining) {
			expected_size = remaining;
		}

		uint8_t *stored = malloc(stored_size);

		if (!stored) {
			free(output);
			free(offsets);
			return NULL;
		}

		if (fseek(fp, (long)(block->file_offset + start), SEEK_SET) != 0) {
			perror("fseek");

			free(stored);
			free(output);
			free(offsets);

			return NULL;
		}

		if (fread(stored, 1, stored_size, fp) != stored_size) {
			fprintf(stderr, "failed reading sector %u: %s\n", i, filename);

			free(stored);
			free(output);
			free(offsets);

			return NULL;
		}

		if (decompress_sector(stored, stored_size, output + output_position, expected_size) != 0) {
			fprintf(stderr, "failed decompressing sector %u: %s\n", i, filename);

			free(stored);
			free(output);
			free(offsets);

			return NULL;
		}

		free(stored);
		output_position += expected_size;
	}

	free(offsets);
	*result_size = block->file_size;

	return output;
}

static int create_directory(const char *path) {
	if (mkdir(path, 0755) == 0) {
		return 0;
	}

	if (errno == EEXIST) {
		return 0;
	}

	perror(path);

	return -1;
}

static int create_parent_directories(char *path) {
	// Walk:
	// output/Interface/WorldMap/foo.blp
	// and temporarily terminate the string at each slash.

	for (char *p = path + 1; *p; p++) {
		if (*p != '/') {
			continue;
		}

		*p = '\0';

		if (create_directory(path) != 0) {
			*p = '/';
			return -1;
		}

		*p = '/';
	}

	return 0;
}

static int valid_mpq_path(const char *filename) {
	if (!filename || !*filename) {
		return 0;
	}

	// MPQ names must be relative: no leading separator, no drive letter.
	if (filename[0] == '/' || filename[0] == '\\') {
		return 0;
	}

	if (isalpha((unsigned char)filename[0]) && filename[1] == ':') {
		return 0;
	}

	// Reject ".." that ends a component. A ".." elsewhere (foo..bar) is a legal name.
	for (const char *p = filename; *p; p++) {
		if (p[0] == '.' && p[1] == '.' && (p[2] == '\0' || p[2] == '/' || p[2] == '\\')) {
			return 0;
		}
	}

	return 1;
}

static int extract_file(FILE *fp, const MPQHeader *header, MPQHashEntry *hash_table, MPQBlockEntry *block_table, const char *filename, const char *output_dir) {
	if (!valid_mpq_path(filename)) {
		fprintf(stderr, "unsafe path skipped: %s\n", filename);
		return -1;
	}

	size_t size = 0;
	void *data = mpq_read_file(fp, header, hash_table, block_table, filename, &size);

	if (!data) {
		fprintf(stderr, "FAILED: %s\n", filename);
		return -1;
	}

	size_t needed = strlen(output_dir) + strlen(filename) + 2;
	char *path = malloc(needed);

	if (!path) {
		free(data);
		return -1;
	}

	snprintf(path, needed, "%s/%s", output_dir, filename);

	// MPQ uses backslashes.
	// Convert them to Unix separators.
	for (char *p = path; *p; p++) {
		if (*p == '\\') {
			*p = '/';
		}
	}

	if (create_parent_directories(path) != 0) {
		free(path);
		free(data);
		return -1;
	}

	FILE *out = fopen(path, "wb");

	if (!out) {
		perror(path);
		free(path);
		free(data);
		return -1;
	}

	if (size > 0 && fwrite(data, 1, size, out) != size) {
		fprintf(stderr, "failed writing: %s\n", path);
		fclose(out);
		free(path);
		free(data);

		return -1;
	}

	fclose(out);

	printf("%s\n", path);

	free(path);
	free(data);

	return 0;
}

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s archive.mpq output_directory\n", argv[0]);
		return 1;
	}

	const char *archive_path = argv[1];
	const char *output_dir = argv[2];

	mpq_init_crypt_table();

	FILE *fp = fopen(archive_path, "rb");

	if (!fp) {
		perror(archive_path);
		return 1;
	}

	MPQHeader header;

	if (fread(&header, sizeof(header), 1, fp) != 1) {
		fprintf(stderr, "failed to read MPQ header\n");
		fclose(fp);
		return 1;
	}

	if (header.signature != MPQ_SIGNATURE) {
		fprintf(stderr, "not an MPQ archive\n");
		fclose(fp);
		return 1;
	}

	printf("MPQ: %s\n", archive_path);
	printf("files/blocks: %u\n", header.block_table_entries);
	printf("sector size: %u\n\n", 512u << header.sector_size_shift);

	uint32_t hash_key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);

	MPQHashEntry *hash_table = read_table(fp, header.hash_table_offset, header.hash_table_entries, sizeof(MPQHashEntry), hash_key);
	if (!hash_table) {
		fclose(fp);
		return 1;
	}

	uint32_t block_key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);

	MPQBlockEntry *block_table = read_table(fp, header.block_table_offset, header.block_table_entries, sizeof(MPQBlockEntry), block_key);
	if (!block_table) {
		free(hash_table);
		fclose(fp);
		return 1;
	}

	size_t listfile_size = 0;
	uint8_t *listfile = mpq_read_file(fp, &header, hash_table, block_table, "(listfile)", &listfile_size);

	if (!listfile) {
		fprintf(stderr, "archive has no readable (listfile)\n");
		free(block_table);
		free(hash_table);
		fclose(fp);
		return 1;
	}

	char *files = malloc(listfile_size + 1);

	if (!files) {
		perror("malloc");
		free(listfile);
		free(block_table);
		free(hash_table);
		fclose(fp);
		return 1;
	}

	memcpy(files, listfile, listfile_size);
	files[listfile_size] = '\0';
	free(listfile);

	// Create root output directory.
	if (create_directory(output_dir) != 0) {
		free(files);
		free(block_table);
		free(hash_table);
		fclose(fp);
		return 1;
	}

	printf("Extracting to: %s\n\n", output_dir);

	// Walk listfile manually.
	// We don't use strtok here because doing it ourselves
	// makes CR/LF handling explicit.

	size_t extracted = 0;
	size_t failed = 0;
	char *p = files;

	while (*p) {
		char *line = p;

		while (*p && *p != '\r' && *p != '\n') {
			p++;
		}

		if (*p) {
			*p++ = '\0';

			// Consume the other half of CRLF.
			while (*p == '\r' || *p == '\n') {
				p++;
			}
		}

		if (!*line) {
			continue;
		}

		// Don't recursively extract our listfile if it happens to be listed.
		if (strcmp(line, "(listfile)") == 0) {
			continue;
		}

		if (extract_file(fp, &header, hash_table, block_table, line, output_dir) == 0) {
			extracted++;
		} else {
			failed++;
		}
	}

	printf("\n");
	printf("Done.\n");
	printf("Extracted: %zu\n", extracted);
	printf("Failed:    %zu\n", failed);

	free(files);
	free(block_table);
	free(hash_table);

	fclose(fp);

	return failed == 0 ? 0 : 2;
}
