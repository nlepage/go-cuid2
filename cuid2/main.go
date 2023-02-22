package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/nlepage/go-cuid2"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "cuid2",
		Usage: "Generate secure, collision-resistant ids",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "big",
				Aliases: []string{"b"},
				Value:   false,
				Usage:   "use a length of 32 characters",
			},
			&cli.IntFlag{
				Name:    "length",
				Aliases: []string{"l"},
				Value:   cuid2.DefaultLength,
				Usage:   "length in characters",
			},
			&cli.StringFlag{
				Name:    "fingerprint",
				Aliases: []string{"f"},
				Usage:   "fingerprint used to help prevent collisions when generating ids in a distributed system",
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.IsSet("big") && ctx.IsSet("length") {
				return errors.New("--big and --length flags must not be used together")
			}

			var length int
			if ctx.Bool("big") {
				length = cuid2.BigLength
			} else {
				length = ctx.Int("length")
			}

			fingerprint := ctx.String("fingerprint")

			createId, err := cuid2.Init(cuid2.Options{
				Length:      length,
				Fingerprint: fingerprint,
			})
			if err != nil {
				return err
			}

			id, err := createId()
			if err != nil {
				return err
			}

			_, err = fmt.Println(id)
			return err
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
