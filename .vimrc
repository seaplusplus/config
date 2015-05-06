set nocompatible        " Use Vim defaults (much better!)

setlocal spell spelllang=en_gb
set spell!

set bs=2                " Allow backspacing over everything in insert mode
set ai                  " Always set auto-indenting on
set smarttab
"set visualbell		" no more beeps
set nobackup		" no .bak file
set smartindent
set history=50          " keep 50 lines of command history
set ruler               " Show the cursor position all the time
set background=dark
set number
set viminfo='20,\"500   " Keep a .viminfo file.
set nowrap
map <F8> :set number!<CR>
map <F7> :set ai!<cr>
map <F6> :set wrap!<cr>
map <F5> :set spell!<cr>
"highlight LineNr ctermfg=darkred ctermbg=darkgray
"highlight Normal ctermfg=darkgray ctermbg=black
"highlight LineNr ctermfg=grey
if has("syntax")
    syntax on             " Default to no syntax highlightning 
endif

set backspace=2		" allow backspacing over everything in insert mode
set suffixes=.bak,~,.swp,.o,.info,.aux,.log,.dvi,.bbl,.blg,.brf,.cb,.ind,.idx,.ilg,.inx,.out,.toc

" Make vim consult the external termcap entries first, so we get all of
" Debian's termcap settings correct. This will be fixed upstream in 5.4
set nottybuiltin term=$TERM
" We know xterm-debian is a color terminal
if &term =~ "xterm-debian" || &term =~ "xterm-xfree86" 
  set t_Co=16
  set t_Sf=[3%dm
  set t_Sb=[4%dm
endif

" enbale color for color-xterm, assuming including debian xterms. (HOPE! :) )
if has("terminfo")
  set t_Co=8
  set t_Sf=[3%p1%dm
  set t_Sb=[4%p1%dm
else
  set t_Co=8
  set t_Sf=[3%dm
  set t_Sb=[4%dm
endif
