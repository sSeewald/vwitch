package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/sseewald/vwitch/internal/api"
	"github.com/sseewald/vwitch/internal/config"
	"github.com/sseewald/vwitch/internal/daemon"
	"github.com/sseewald/vwitch/internal/portal"
	"github.com/sseewald/vwitch/internal/state"
	"github.com/sseewald/vwitch/internal/version"
	"github.com/sseewald/vwitch/internal/web"
)

func serveCmd(g *globals) *cobra.Command {
	var stateDir string
	var debug, initMissing bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the daemon (systemd runs this)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			level := slog.LevelInfo
			if debug {
				level = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			if initMissing {
				if err := initFromEnv(g.config, log); err != nil {
					return err
				}
			}
			cfg, err := config.Open(g.config)
			if err != nil {
				return err
			}
			st, err := state.Open(stateDir)
			if err != nil {
				return err
			}
			sys, err := daemon.NewSystem(log)
			if err != nil {
				return err
			}
			defer func() { _ = sys.Close() }()
			d := daemon.New(cfg, st, sys, log)
			r, err := web.NewRenderer()
			if err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			reload := make(chan os.Signal, 1)
			signal.Notify(reload, syscall.SIGHUP)
			go func() {
				for range reload {
					if err := d.Reload(); err != nil {
						log.Error("reload", "err", err)
					}
				}
			}()

			ln, err := api.Listen(g.socket)
			if err != nil {
				return err
			}
			apiSrv := &http.Server{Handler: api.Handler(d)}

			eg, ctx := errgroup.WithContext(ctx)
			eg.Go(func() error { return d.Run(ctx) })
			eg.Go(func() error { return portal.New(d, r, log).Serve(ctx) })
			eg.Go(func() error { return web.NewAdmin(d, r, log, stateDir).Serve(ctx) })
			eg.Go(func() error {
				go func() { <-ctx.Done(); _ = apiSrv.Close() }()
				if err := apiSrv.Serve(ln); err != http.ErrServerClosed {
					return err
				}
				return nil
			})
			log.Info("vwitch started", "version", version.String(), "config", g.config)
			return eg.Wait()
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", config.DefaultStateDir, "runtime state directory")
	cmd.Flags().BoolVar(&debug, "debug", false, "verbose logging")
	cmd.Flags().BoolVar(&initMissing, "init", false, "create the configuration from VWITCH_* environment variables if it is missing (containers)")
	return cmd
}
