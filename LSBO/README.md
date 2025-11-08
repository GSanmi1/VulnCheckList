### Description.

A *Linear Stack Buffer Overflow* is a vulnerability in which a contiguous fixed-size stack memory region gets stuffed with an amount of data bigger than the storage capacity of the structure resulting in the overwriting of adyacent memory regions.

<br>

### Discover.

In order to find potentials LSBOs on C code we go on the following steps:

- First, a *Linear Stack Buffer Overflow* affects the overflow of contiguous memory structures in the stack, so the first thing we'll do is identify these structures in the code, specifically within a function:

   -> Structs defined within the function itself.
   -> Buffers or arrays defined within the function itself.

- Next, we'll review the function (and calls to other functions made by that function) to try to find write operations on these structures.

   -> "Weakly-bounded functions" such as memcpy(), sprintf(), etc.
   -> "for" loops, "while" loops, etc. where assignment operations or other operations are performed.

Once these operations are located, we'll trace back the path to that operation in the function, focusing on finding:

   -> Possible restrictions or sanitization operations that could halt the execution of the data copy operation on the structure. For example, an if statement that evaluates whether the size of the data to be copied cannot exceed the size of the destination structure.
   -> The origin of the data being copied onto the structure and whether or not they are controlled by the user at any point along the path.

We define a Stack Buffer Overflow as a data transfer operation of user-controlled data onto a fixed-size structure in the stack without restrictions that limit said operation.

<br>

### Examples.

As brief examples we can see the following code fragment from CVE-2021-20294 in which a local buffer (buffer\[256\]) gets filled by a weakly-bounded function (sprintf) with user-controlled data (filedata) with no previous sanitation:

```c
static void
print_dynamic_symbol (Filedata *filedata, unsigned long si,
		      Elf_Internal_Sym *symtab,
		      Elf_Internal_Shdr *section,
		      char *strtab, size_t strtab_size)
{
  const char *version_string;
  enum versioned_symbol_info sym_info;
  unsigned short vna_other;
  Elf_Internal_Sym *psym = symtab + si;
  
  printf ("%6ld: ", si);
  print_vma (psym->st_value, LONG_HEX);
  putchar (' ');
  print_vma (psym->st_size, DEC_5);
  printf (" %-7s", get_symbol_type (filedata, ELF_ST_TYPE (psym->st_info)));
  printf (" %-6s", get_symbol_binding (filedata, ELF_ST_BIND (psym->st_info)));
  if (filedata->file_header.e_ident[EI_OSABI] == ELFOSABI_SOLARIS)
    printf (" %-7s",  get_solaris_symbol_visibility (psym->st_other));
  else
    {
      unsigned int vis = ELF_ST_VISIBILITY (psym->st_other);

      printf (" %-7s", get_symbol_visibility (vis));
      /* Check to see if any other bits in the st_other field are set.
	 Note - displaying this information disrupts the layout of the
	 table being generated, but for the moment this case is very rare.  */
      if (psym->st_other ^ vis)
	printf (" [%s] ", get_symbol_other (filedata, psym->st_other ^ vis));
    }
  printf (" %4s ", get_symbol_index_type (filedata, psym->st_shndx));

  bfd_boolean is_valid = VALID_SYMBOL_NAME (strtab, strtab_size,
					    psym->st_name);
  const char * sstr = is_valid  ? strtab + psym->st_name : _("");

  version_string
    = get_symbol_version_string (filedata,
				 (section == NULL
				  || section->sh_type == SHT_DYNSYM),
				 strtab, strtab_size, si,
				 psym, &sym_info, &vna_other); 
  
  int len_avail = 21;
  if (! do_wide && version_string != NULL) 
    {
      char buffer[256];

      len_avail -= sprintf(buffer, "@%s", version_string);

      if (sym_info == symbol_undefined)
	len_avail -= sprintf (buffer," (%d)", vna_other);
      else if (sym_info != symbol_hidden)
	len_avail -= 1;
    }

  print_symbol (len_avail, sstr);
// ...
}
```


Other example, would be the following code regarding CVE-2021-43549, in which again a weakly-bounded function (fread) fills a local-defined buffer (colormap\[256\]\[4\]) with user-controlled data (fp):

```c
static int                       /* O - 0 = success, -1 = fail */
image_load_bmp(image_t *img,     /* I - Image to load into */
               FILE    *fp,      /* I - File to read from */
               int     gray,     /* I - Grayscale image? */
               int     load_data)/* I - 1 = load image data, 0 = just info */
{
  int   info_size,	/* Size of info header */
        depth,		/* Depth of image (bits) */
        compression,	/* Type of compression */
        colors_used,	/* Number of colors used */
        x, y,		/* Looping vars */
        color,		/* Color of RLE pixel */
        count,		/* Number of times to repeat */
        temp,		/* Temporary color */
        align;		/* Alignment bytes */
        uchar bit,	/* Bit in image */
        byte;		/* Byte in image */
        uchar *ptr;	/* Pointer into pixels */
        uchar		colormap[256][4];/* Colormap */


  // Get the header...
  getc(fp);			/* Skip "BM" sync chars */
  getc(fp);
  read_dword(fp);		/* Skip size */
  read_word(fp);		/* Skip reserved stuff */
  read_word(fp);
  read_dword(fp);

  // Then the bitmap information...
  info_size        = (int)read_dword(fp);
  img->width       = read_long(fp);
  img->height      = read_long(fp);
  read_word(fp);
  depth            = read_word(fp);
  compression      = (int)read_dword(fp);
  read_dword(fp);
  read_long(fp);
  read_long(fp);
  colors_used      = (int)read_dword(fp);
  read_dword(fp);

  if (img->width <= 0 || img->width > 8192 || img->height <= 0 || img->height > 8192)
    return (-1);

  if (info_size > 40)
    for (info_size -= 40; info_size > 0; info_size --)
      getc(fp);

  // Get colormap...
  if (colors_used == 0 && depth <= 8)
    colors_used = 1 << depth;

  fread(colormap, (size_t)colors_used, 4, fp);
//...
```