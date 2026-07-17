/*
 * Copyright (C) 2020-2021 Fred Posner (palner.com)
 *
 * This file is part of APIBAN.org.
 *
 * apiban-iptables-client is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * apiban-iptables-client is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Example build commands:
 * GOOS=linux GOARCH=amd64 go build -o apiban-iptables-client
 * GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o apiban-iptables-client
 * GOOS=linux GOARCH=arm GOARM=7 go build -o apiban-iptables-client-pi
 */

package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apiban/golib"
	"github.com/coreos/go-iptables/iptables"
)

var configFileLocation string
var logFile string
var targetChain string
var skipVerify string

func init() {
	flag.StringVar(&targetChain, "target", "REJECT", "target chain for matching entries")
	flag.StringVar(&configFileLocation, "config", "", "location of configuration file")
	flag.StringVar(&logFile, "log", "/var/log/apiban-client.log", "location of log file or - for stdout")
	flag.StringVar(&skipVerify, "verify", "true", "set to false to skip verify of tls cert")

	if skipVerify == "false" {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

// ApibanConfig is the structure for the JSON config file
type ApibanConfig struct {
	APIKEY     string `json:"apikey"`
	LKID       string `json:"lkid"`
	VERSION    string `json:"version"`
	FLUSH      string `json:"flush"`
	SET        string `json:"set"`
	IPSET      bool   `json:"ipset,omitempty"`
	CHAIN      string `json:"chain,omitempty"`
	Allowed    []IPNet
	sourceFile string
}

type IPNet struct {
	Cidr string `json:"cidr,omitempty"`
}

// Function to see if string within string
func Contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

// Function to see if string (cidr) contains ip (string)
func ContainsIP(cidrstring string, ip string) bool {
	// make sure cidrstring is a valid cidr network. Ignore ip and get the network part.
	_, netw, err := net.ParseCIDR(cidrstring)
	if err != nil {
		return false
	}

	// make sure ip is an ip
	ipaddress := net.ParseIP(ip)
	if ipaddress == nil {
		return false
	}

	// check if valid ipaddress is in valid network
	if netw.Contains(ipaddress) {
		return true
	}

	return false
}

func ContainsPartial(list []string, value string) bool {
	for _, val := range list {
		if strings.Contains(val, " "+value+" ") {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()

	defer os.Exit(0)

	// Open our Log
	if logFile != "-" && logFile != "stdout" {
		lf, err := os.OpenFile("/var/log/apiban-client.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	log.Print("** Started APIBAN CLIENT")
	log.Print("** Licensed under GPLv2. See LICENSE for details.")
	now := time.Now()

	// Open our config file
	apiconfig, err := LoadConfig()
	if err != nil {
		log.Fatalln(err)
		runtime.Goexit()
	}

	// if no APIKEY, exit
	if apiconfig.APIKEY == "" {
		log.Fatalln("Invalid APIKEY. Exiting.")
		runtime.Goexit()
	}

	// if no APIKEY, exit
	if apiconfig.APIKEY == "MY API KEY" {
		log.Fatalln("Invalid APIKEY. Exiting. Go to apiban.org and get an api key.")
		runtime.Goexit()
	}

	// allow cli of FULL to reset LKID to 100
	if len(os.Args) > 1 {
		arg1 := os.Args[1]
		if arg1 == "FULL" {
			log.Print("CLI of FULL received, resetting LKID")
			apiconfig.LKID = "100"
		}
	} else {
		log.Print("no command line arguments received")
	}

	// if no LKID, reset it to 100
	if len(apiconfig.LKID) == 0 {
		log.Print("Resetting LKID")
		apiconfig.LKID = "100"
	}

	// if no LKID, reset it to 100
	if len(apiconfig.FLUSH) == 0 {
		log.Print("Resetting FLUSH")
		flushnow := now.Unix()
		apiconfig.FLUSH = strconv.FormatInt(flushnow, 10)
	}

	// tag to version of this script
	apiconfig.VERSION = "2.0"
	if apiconfig.CHAIN == "" {
		log.Println("no chain provided, using APIBAN")
		apiconfig.CHAIN = "APIBAN"
	}

	// Go connect for IPTABLES
	ipt, err := iptables.New()
	if err != nil {
		log.Panic(err)
	}

	iptinit, err := initializeIPTables(ipt, apiconfig)
	if err != nil {
		log.Fatalln("failed to initialize IPTables:", err)
	}

	if iptinit == "chain created" {
		log.Print("APIBAN chain was created - Resetting LKID")
		apiconfig.LKID = "100"
	}

	flushtime, _ := strconv.ParseInt(apiconfig.FLUSH, 10, 64)
	flushdiff := now.Unix() - flushtime
	if flushdiff >= 604800 {
		if apiconfig.IPSET {
			err = IpsetFlush(apiconfig.CHAIN)
			if err != nil {
				log.Println("Flushing", apiconfig.CHAIN, "ipset failed. ", err.Error())
			} else {
				log.Println("Flushed", apiconfig.CHAIN, "ipset.")
			}
		} else {
			err = ipt.ClearChain("filter", apiconfig.CHAIN)
			if err != nil {
				log.Println("Flushing", apiconfig.CHAIN, "chain failed. ", err.Error())
			} else {
				log.Println(apiconfig.CHAIN, "chain flushed")
			}
		}

		apiconfig.LKID = "100"
		apiconfig.FLUSH = strconv.FormatInt(now.Unix(), 10)
	}

	i := 0
	for i < 24 {
		log.Println("Checking banned list with ID", apiconfig.LKID, "settype", apiconfig.SET)
		// Get list of banned ip's from APIBAN.org (up to 24 times)
		res, err := golib.Banned(apiconfig.APIKEY, apiconfig.LKID, apiconfig.SET)
		if err != nil {
			log.Fatalln("failed to get banned list:", err)
			continue
		}

		if res.ID == apiconfig.LKID {
			log.Print("Great news... no new bans to add. Exiting...")
			if err := apiconfig.Update(); err != nil {
				log.Fatalln(err)
			}
			os.Exit(0)
		}

		if len(res.IPs) == 0 {
			log.Print("No IP addresses detected. Exiting.")
			os.Exit(0)
		}

		for _, ip := range res.IPs {
			blocktheip := true
			// check if ip is in allowed
			if apiconfig.Allowed != nil {
				for _, v := range apiconfig.Allowed {
					if ContainsIP(v.Cidr, ip) {
						log.Println("** not blocking", ip, "--", v.Cidr, "is in allowed")
						blocktheip = false
					}
				}
			}

			if blocktheip {
				if apiconfig.IPSET {
					err = IpsetAddIp(apiconfig.CHAIN, ip)
				} else {
					blockedip := ip + "/32"
					err = ipt.AppendUnique("filter", apiconfig.CHAIN, "-s", blockedip, "-d", "0/0", "-j", targetChain)
				}

				if err != nil {
					log.Print("Adding rule failed. ", err.Error())
				} else {
					log.Print("Blocking ", ip)
				}
			}
		}

		apiconfig.LKID = res.ID
	}

	// update config
	if err := apiconfig.Update(); err != nil {
		log.Fatalln(err)
	}

	log.Print("** Done. Exiting.")
}

// LoadConfig attempts to load the APIBAN configuration file from various locations
func LoadConfig() (*ApibanConfig, error) {
	var fileLocations []string

	// If we have a user-specified configuration file, use it preferentially
	if configFileLocation != "" {
		fileLocations = append(fileLocations, configFileLocation)
	}

	// If we can determine the user configuration directory, try there
	configDir, err := os.UserConfigDir()
	if err == nil {
		fileLocations = append(fileLocations, fmt.Sprintf("%s/apiban/config.json", configDir))
	}

	// Add standard static locations
	fileLocations = append(fileLocations,
		"/etc/apiban/config.json",
		"config.json",
		"/usr/local/bin/apiban/config.json",
	)

	for _, loc := range fileLocations {
		f, err := os.Open(loc)
		if err != nil {
			continue
		}
		defer f.Close()

		cfg := new(ApibanConfig)
		if err := json.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("failed to read configuration from %s: %w", loc, err)
		}

		// Store the location of the config file so that we can update it later
		cfg.sourceFile = loc

		return cfg, nil
	}

	return nil, errors.New("failed to locate configuration file")
}

// Update rewrite the configuration file with and updated state (such as the LKID)
func (cfg *ApibanConfig) Update() error {
	f, err := os.Create(cfg.sourceFile)
	if err != nil {
		return fmt.Errorf("failed to open configuration file for writing: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")
	return enc.Encode(cfg)
}

func initializeIPTables(ipt *iptables.IPTables, apiconfig *ApibanConfig) (string, error) {
	// Get existing chains from IPTABLES
	originaListChain, err := ipt.ListChains("filter")
	if err != nil {
		return "error", fmt.Errorf("failed to read iptables: %w", err)
	}

	// Search for INPUT in IPTABLES
	chain := "INPUT"
	if !Contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected INPUT chain")
	}

	// Search for FORWARD in IPTABLES
	chain = "FORWARD"
	if !Contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected FORWARD chain")
	}

	// if ipset, check if rule exists (and make ipset). If iptables, check that chain exists
	if apiconfig.IPSET {
		log.Println("Using ipset...")
		rules, err := ipt.List("filter", "INPUT")
		if err != nil {
			log.Println("Listing of INPUT rules failed:", err.Error())
			return "error", err
		}

		if !ContainsPartial(rules, apiconfig.CHAIN) {
			log.Println("INPUT doesn't contain", apiconfig.CHAIN, " rule - Creating now...")
			err = IpsetNew(apiconfig.CHAIN)
			if err != nil {
				log.Println("ipset create received:", err.Error())
			}

			// iptables -A INPUT -m set --match-set APIBAN src -j DROP
			err = ipt.AppendUnique("filter", "INPUT", "-m", "set", "--match-set", apiconfig.CHAIN, "src", "-j", targetChain)
			if err != nil {
				return "error", fmt.Errorf("failed to add ipset rule to INPUT chain: %w", err)
			}

			return "chain created", nil
		}

		return "ipset rule exists", nil
	} else {
		log.Println("using iptables directly")

		// Search for APIBAN in IPTABLES
		if Contains(originaListChain, apiconfig.CHAIN) {
			// APIBAN chain already exists
			return "chain exists", nil
		}

		log.Println("IPTABLES doesn't contain", apiconfig.CHAIN, "- Creating now...")

		// Add APIBAN chain
		err = ipt.ClearChain("filter", apiconfig.CHAIN)
		if err != nil {
			return "error", fmt.Errorf("failed to clear chain: %w", err)
		}

		// Add APIBAN chain to INPUT
		err = ipt.Insert("filter", "INPUT", 1, "-j", apiconfig.CHAIN)
		if err != nil {
			return "error", fmt.Errorf("failed to add chain to INPUT chain: %w", err)
		}

		// Add APIBAN chain to FORWARD
		err = ipt.Insert("filter", "FORWARD", 1, "-j", apiconfig.CHAIN)
		if err != nil {
			return "error", fmt.Errorf("failed to add chain to FORWARD chain: %w", err)
		}

		return "chain created", nil
	}
}

func IpsetNew(setname string) error {
	path, err := exec.LookPath("ipset")
	if err != nil {
		return err
	}

	cmd := exec.Command(path, "create", setname, "hash:ip", "-exist")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func IpsetAddIp(setname string, ip string) error {
	path, err := exec.LookPath("ipset")
	if err != nil {
		return err
	}

	cmd := exec.Command(path, "add", setname, ip, "-exist")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func IpsetFlush(setname string) error {
	path, err := exec.LookPath("ipset")
	if err != nil {
		return err
	}

	cmd := exec.Command(path, "flush", setname)
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
