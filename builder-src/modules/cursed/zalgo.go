package cursed

/*
THIS IS ALL TAKEN DIRECTLY FROM https://github.com/wayneashleyberry/eeemo without this repo I would be nothing smh.
*/

import (
	"math/rand"
	"strings"
)

var zalgoUp []string
var zalgoDown []string
var zalgoMid []string

func init() {
	// those go UP
	zalgoUp = []string{
		"\u030d" /*     ̍     */, "\u030e" /*     ̎     */, "\u0304" /*     ̄     */, "\u0305", /*     ̅     */
		"\u033f" /*     ̿     */, "\u0311" /*     ̑     */, "\u0306" /*     ̆     */, "\u0310", /*     ̐     */
		"\u0352" /*     ͒     */, "\u0357" /*     ͗     */, "\u0351" /*     ͑     */, "\u0307", /*     ̇     */
		"\u0308" /*     ̈     */, "\u030a" /*     ̊     */, "\u0342" /*     ͂     */, "\u0343", /*     ̓     */
		"\u0344" /*     ̈́     */, "\u034a" /*     ͊     */, "\u034b" /*     ͋     */, "\u034c", /*     ͌     */
		"\u0303" /*     ̃     */, "\u0302" /*     ̂     */, "\u030c" /*     ̌     */, "\u0350", /*     ͐     */
		"\u0300" /*     ̀     */, "\u0301" /*     ́     */, "\u030b" /*     ̋     */, "\u030f", /*     ̏     */
		"\u0312" /*     ̒     */, "\u0313" /*     ̓     */, "\u0314" /*     ̔     */, "\u033d", /*     ̽     */
		"\u0309" /*     ̉     */, "\u0363" /*     ͣ     */, "\u0364" /*     ͤ     */, "\u0365", /*     ͥ     */
		"\u0366" /*     ͦ     */, "\u0367" /*     ͧ     */, "\u0368" /*     ͨ     */, "\u0369", /*     ͩ     */
		"\u036a" /*     ͪ     */, "\u036b" /*     ͫ     */, "\u036c" /*     ͬ     */, "\u036d", /*     ͭ     */
		"\u036e" /*     ͮ     */, "\u036f" /*     ͯ     */, "\u033e" /*     ̾     */, "\u035b", /*     ͛     */
		"\u0346" /*     ͆     */, "\u031a", /*     ̚     */
	}

	// those go DOWN
	zalgoDown = []string{
		"\u0316" /*     ̖     */, "\u0317" /*     ̗     */, "\u0318" /*     ̘     */, "\u0319", /*     ̙     */
		"\u031c" /*     ̜     */, "\u031d" /*     ̝     */, "\u031e" /*     ̞     */, "\u031f", /*     ̟     */
		"\u0320" /*     ̠     */, "\u0324" /*     ̤     */, "\u0325" /*     ̥     */, "\u0326", /*     ̦     */
		"\u0329" /*     ̩     */, "\u032a" /*     ̪     */, "\u032b" /*     ̫     */, "\u032c", /*     ̬     */
		"\u032d" /*     ̭     */, "\u032e" /*     ̮     */, "\u032f" /*     ̯     */, "\u0330", /*     ̰     */
		"\u0331" /*     ̱     */, "\u0332" /*     ̲     */, "\u0333" /*     ̳     */, "\u0339", /*     ̹     */
		"\u033a" /*     ̺     */, "\u033b" /*     ̻     */, "\u033c" /*     ̼     */, "\u0345", /*     ͅ     */
		"\u0347" /*     ͇     */, "\u0348" /*     ͈     */, "\u0349" /*     ͉     */, "\u034d", /*     ͍     */
		"\u034e" /*     ͎     */, "\u0353" /*     ͓     */, "\u0354" /*     ͔     */, "\u0355", /*     ͕     */
		"\u0356" /*     ͖     */, "\u0359" /*     ͙     */, "\u035a" /*     ͚     */, "\u0323", /*     ̣     */
	}

	// those always stay in the middle
	zalgoMid = []string{
		"\u0315" /*     ̕     */, "\u031b" /*     ̛     */, "\u0340" /*     ̀     */, "\u0341", /*     ́     */
		"\u0358" /*     ͘     */, "\u0321" /*     ̡     */, "\u0322" /*     ̢     */, "\u0327", /*     ̧     */
		"\u0328" /*     ̨     */, "\u0334" /*     ̴     */, "\u0335" /*     ̵     */, "\u0336", /*     ̶     */
		"\u034f" /*     ͏     */, "\u035c" /*     ͜     */, "\u035d" /*     ͝     */, "\u035e", /*     ͞     */
		"\u035f" /*     ͟     */, "\u0360" /*     ͠     */, "\u0362" /*     ͢     */, "\u0338", /*     ̸     */
		"\u0337" /*     ̷     */, "\u0361" /*     ͡     */, "\u0489", /*     ҉_     */
	}
}

// Generate will run the zalgo text generator against the input.
func Generate(txt string, size string, up bool, middle bool, down bool) string {
	newtxt := ""

	for _, c := range strings.Split(txt, "") {
		if isZalgoChar(c) {
			continue
		}

		var numUp, numMid, numDown int

		newtxt += string(c)

		if size == "mini" {
			numUp = rand.Intn(8)
			numMid = rand.Intn(2)
			numDown = rand.Intn(8)
		} else if size == "normal" {
			numUp = rand.Intn(16)/2 + 1
			numMid = rand.Intn(6) / 2
			numDown = rand.Intn(16)/2 + 1
		} else { // maxi
			numUp = rand.Intn(64)/4 + 3
			numMid = rand.Intn(16)/4 + 1
			numDown = rand.Intn(64)/4 + 3
		}

		if up {
			for j := 0; j < numUp; j++ {
				newtxt += randZalgo(zalgoUp)
			}
		}

		if middle {
			for j := 0; j < numMid; j++ {
				newtxt += randZalgo(zalgoMid)
			}
		}

		if down {
			for j := 0; j < numDown; j++ {
				newtxt += randZalgo(zalgoDown)
			}
		}
	}

	return newtxt
}

// randZalgo gets a random char from a zalgo char table
func randZalgo(array []string) string {
	index := rand.Intn(len(array))
	return array[index]
}

// isZalgoChar will lookup char to know if its a zalgo char or not
func isZalgoChar(c string) bool {
	for _, cc := range zalgoUp {
		if c == cc {
			return true
		}
	}

	for _, cc := range zalgoMid {
		if c == cc {
			return true
		}
	}

	for _, cc := range zalgoDown {
		if c == cc {
			return true
		}
	}

	return false
}
