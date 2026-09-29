# Extracts files from MPQ archives

This tool extracts files from MPQ (MoPaQ) archive format used in many games such
as World of Warcraft, StarCraft and Diablo II.

It supports ZLIB compression and can handle both sector-based and single-unit
files. It relies on the internal `(listfile)` for filename resolution.

> [!NOTE]
> It should work on all operating systems. There is no special code in this
> repository or any dependencies you need to have installed on your machine.
> C compiler and Libc is all you need.

## Compile & Use

```sh
make -B
```

This will create `mpqextract` binary. Check available options with
`./mpqextract`.

Basic example of usage is `./mpqextract samples/data.mpq output/`.

## Extraction output

If you run the program, it will output the archive details and progress.

```sh
$ ./mpqextract samples/data.mpq output/
MPQ: samples/data.mpq
files/blocks: 1240
sector size: 4096

Extracting to: output/

output/Interface/WorldMap/WorldMap.xml
output/Interface/WorldMap/WorldMap.lua
output/Interface/WorldMap/WorldMapButton.xml
...

Done.
Extracted: 1238
Failed:    2
```


> [!IMPORTANT]
> The program requires a valid `(listfile)` within the archive to know which
> files to extract.

## Reading material

- http://www.zezula.net/en/mpq/stormlib.html
- https://wowdev.wiki/MPQ

## Special thanks

- https://github.com/richgel999/miniz

## License

[mpqextract](https://github.com/mitjafelicijan/mpqextract) was written by [Mitja
Felicijan](https://mitjafelicijan.com) and is released under the BSD
two-clause license, see the LICENSE file for more information.
