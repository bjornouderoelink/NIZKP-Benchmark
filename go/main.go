package main

import (
	"log"
	"nizkp_benchmark/internal/hash"
)

func main() {
	log.Println("Running MiMC hash...")
	hash.Run()
	log.Println("Finished MiMC hash!")
}
