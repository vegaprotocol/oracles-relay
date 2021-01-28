package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"code.vegaprotocol.io/oracles-relay/coinbase"
)

var flags = struct {
	Config string
}{}

func init() {
	flag.StringVar(&flags.Config, "config", "config.toml", "The configuration of the oracle relay")
}

func main() {
	flag.Parse()

	// load our configuration
	config, err := loadConfig(flags.Config)
	if err != nil {
		log.Printf("unable to read configuration: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan []byte, 1000)

	wg := sync.WaitGroup{}

	// build the specifed workers from the config
	if config.Coinbase != nil {
		wg.Add(1)
		go startWorker(
			ctx, coinbase.New(*config.Coinbase), config.Coinbase.Frequency, ch, &wg,
		)
	}

	// a bunch of signals to catch
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// now we can just listen to updates and send them to vega
	for {
		select {
		case <-sigc:
			cancel()
			wg.Wait()
			return
		case btes := <-ch:
			// at some point we'll send the oracle data to vega
			// for now we dump them :)
			fmt.Printf("%v\n", string(btes))
		}
	}
}

type worker interface {
	Pull() ([]byte, error)
}

func startWorker(
	ctx context.Context,
	w worker,
	freq time.Duration,
	ch chan<- []byte,
	wg *sync.WaitGroup,
) {
	t := time.NewTicker(freq)
	for {
		t.Reset(freq)
		select {
		case <-ctx.Done():
			wg.Done()
			return
		case <-t.C:
			// call worker
			btes, err := w.Pull()
			if err != nil {
				log.Printf("error pulling data from worker: %v", err)
				continue
			}
			ch <- btes
		}
	}
}
