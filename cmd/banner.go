package cmd

import (
	"fmt"

	"icool.io/yat/edge/pkg/config"
)

// Banner YAT ASCII art
const Banner = `
   ____  ____  ____  ____
  ||Y ||||A ||||T |||| ||
  ||__||||__||||__||||__||
  |/__\||/__\||/__\||/__\|

  __   __     _       _____ 
  \ \ / /    / \     |_   _|
   \ V /    / _ \      | |  
    | |    / ___ \     | |  
    |_|   /_/   \_\    |_|  

╔══════════════════════════════════════╗
║   Yet Another Tunnel - Edge Server   ║
║         Secure • Fast • Reliable      ║
╚══════════════════════════════════════╝
`

const Banner3D = `
    ____    ____    ____  
   /\  _\  /\  _\  /\__  \  
   \ \ \/  \ \ \/  \/_/  /__
    \ \_\   \ \_\    /\_____\
     \/_/    \/_/    \/_____/
                             
  __  __     ____     ______  
 /\ \/\ \   /\  _\   /\__  _\ 
 \ \ \_\ \  \ \ \/   \/_/\ \/ 
  \ \_____\  \ \_\      \ \_\ 
   \/_____/   \/_/       \/_/ 

╔═══════════════════════════════════════╗
║    Yet Another Tunnel - Edge Server   ║
║          Secure • Fast • Reliable      ║
╚═══════════════════════════════════════╝
`

const BannerSlant = `
    __  __          ______
    \ \/ /         /_  __/
     \  /    _      / /   
     / /    /_\    / /    
    /_/            /_/     

╔═══════════════════════════════════════╗
║    Yet Another Tunnel - Edge Server   ║
║          Secure • Fast • Reliable      ║
╚═══════════════════════════════════════╝
`

const BannerItalic = `
 ____  ____        _        _________  
|_  _||_  _|      / \      |  _   _  | 
  \ \  / /       / _ \     |_/ | | \_| 
   \ \/ /       / ___ \        | |     
   _|  |_  _  _/ /   \ \_  _  _| |_    
  |______|(_)|____| |____|(_)|_____|   
                                            
 ╔════════════════════════════════════════════╗
 ║     Yet Another Tunnel - Edge Server       ║
 ║           Secure • Fast • Reliable          ║
 ╚════════════════════════════════════════════╝
`

// PrintBanner Print banner
func PrintBanner() {
	version, build, commit, rt := config.GetVersionInfo()
	fmt.Print(BannerItalic)
	fmt.Printf("  Version: %s\n", version)
	fmt.Printf("  Build:   %s\n", build)
	fmt.Printf("  Commit:  %s\n", commit)
	fmt.Printf("  Runtime:  %s\n", rt)
	fmt.Println()
}
