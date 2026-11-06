package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/sseewald/vwitch/internal/firewall"
	"github.com/sseewald/vwitch/internal/geo"
	"github.com/sseewald/vwitch/internal/nflog"
)

func TestDomainBlocking(t *testing.T) {
	d, _, _ := setup(t)
	d.reconcile(context.Background())
	if err := d.BlockDomain("https://Ads.Example/x", "tracker.org"); err != nil {
		t.Fatal(err)
	}
	if got := d.Config().Security.BlockedDomains; len(got) != 2 || got[0] != "ads.example" {
		t.Fatalf("stored %v", got)
	}
	d.reconcile(context.Background())
	client := d.Config().Clients[0].Address
	if s, ok := d.dnsBlock(client, "cdn.ads.example"); !ok || s != "custom" {
		t.Fatal("subdomain not blocked")
	}
	d.dnsSeen(client, "cdn.ads.example", "custom")
	d.dnsSeen(client, "www.ok.test", "")
	if ev := d.BlockLog(10, "domain"); len(ev) != 1 || ev[0].Client != "phone" || ev[0].Domain != "cdn.ads.example" {
		t.Fatalf("log %+v", ev)
	}
	if l := d.Domains("phone"); len(l) != 2 {
		t.Fatalf("activity %+v", l)
	}
	if err := d.UnblockDomain("ads.example"); err != nil {
		t.Fatal(err)
	}
	d.reconcile(context.Background())
	if _, ok := d.dnsBlock(client, "ads.example"); ok {
		t.Fatal("still blocked")
	}
	_ = d.Set("activity", "false")
	d.reconcile(context.Background())
	d.dnsSeen(client, "x.test", "")
	if len(d.Domains("")) != 0 {
		t.Fatal("activity list must stay empty when switched off")
	}
}

func TestRegionBlocking(t *testing.T) {
	d, sys, _ := setup(t)
	if err := d.SetMany([][2]string{{"regions.enabled", "true"}, {"regions.countries", "ru, by"}, {"regions.direction", "outgoing"}}); err != nil {
		t.Fatal(err)
	}
	d.reconcile(context.Background())
	if len(sys.block) != 0 {
		t.Fatal("no rules without the country database")
	}
	db, _ := geo.Parse(strings.NewReader("x|RU|ipv4|5.8.0.0|256|0|allocated\nx|DE|ipv4|2.160.0.0|256|0|allocated\n"))
	d.prot.geo = db
	d.reconcile(context.Background())
	got := firewall.RenderBlock(sys.blockSets, sys.block)
	if !strings.Contains(got, "ip daddr @f0_region_v4 reject") || strings.Contains(got, "saddr") {
		t.Fatalf("outgoing block:\n%s", got)
	}
	if sys.blockSets[0].Ranges[0].From.String() != "5.8.0.0" {
		t.Fatalf("set %+v", sys.blockSets[0])
	}
	d.onBlocked(nflog.Hit{Prefix: firewall.LogPrefix("region", false), Src: d.Config().Clients[0].Address, Dst: sys.blockSets[0].Ranges[0].From, Proto: 6, DPort: 443})
	if ev := d.BlockLog(5, "address"); len(ev) != 1 || ev[0].Country != "RU" || ev[0].Client != "phone" || ev[0].Port != 443 {
		t.Fatalf("hit %+v", ev)
	}
	_ = d.Set("regions.enabled", "false")
	d.reconcile(context.Background())
	if len(sys.block) != 0 {
		t.Fatal("disabled filter must remove the rules")
	}
}
