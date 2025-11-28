import {DOMParser} from 'https://deno.land/x/deno_dom/deno-dom-wasm.ts'
import {parse} from 'https://deno.land/x/date_fns/index.js'
import {fr} from 'https://deno.land/x/date_fns/locale/index.js'

export async function fetchPlayer(username: string, period = 0) {
  const doc = new DOMParser().parseFromString(await fetch(`https://www.funcraft.net/fr/joueurs?q=${username}`).then(res => res.text()), 'text/html')!
  if (doc.getElementsByClassName('alert-container').length !== 0) throw new Error('Player not found')
  const selector = new DOMParser().parseFromString(await fetch(doc.getElementById('player-friends-content')!.getAttribute('data-url')!).then(res => res.text()), 'text/html')!.getElementsByClassName('players-heads')[0].children
  const friends: Array<Record<string, string>> = []
  for (let i = 0; i < selector.length; i++) {
    friends.push({
      nickname: selector[i].getAttribute('title')!,
      avatar: selector[i].children[0].children[0].getAttribute('src')!,
      funcraftURL: selector[i].children[0].getAttribute('href')!
    })
  }
  const data = JSON.parse(doc.querySelectorAll('script')[6]!.textContent.split('=')[2].slice(1, -12))
  const formatData = (game: string, gameNum: number) => {
    const obj: Record<string, number | string> = {}
    if (data[Object.keys(data)[period]][game] !== undefined) {
      for (let i = 0; i < data[Object.keys(data)[period]][game].stats.length; i++) {
        obj[data[Object.keys(data)[period]][game].stats[i].name.replace(/(_[a-z])/gi, (l: string) => l.toUpperCase().replace('_', ''))] = data[Object.keys(data)[period]][game].stats[i].value
      }
      if (obj.gamesWon === undefined) obj.gamesWon = <number>obj.gamesPlayed - <number>obj.gamesLost
      if (obj.gamesLost === undefined) obj.gamesLost = <number>obj.gamesPlayed - <number>obj.gamesWon
      let plus = ''
      let always = 1
      if (period > 0) {
        plus = `.children[${period - 1}]`
        always = 2
      }
      obj.rank = parseInt(new Function('doc', 'gameNum', 'plus', 'always', 'return (doc.querySelectorAll(".player-stats-info")[gameNum].children[1].children[always]' + plus + '.textContent.trim().slice(0, -3))')(doc, gameNum, plus, always)) || 0
      const colors: Record<number, string> = {
        0: '856400',
        1: '947001',
        2: '666c17',
        3: '09467c',
        4: '2c1760',
        5: '184953',
        6: '2e6218',
        7: '8c4701',
        8: '6e1a0a',
        9: '54351c',
        10: '947001'
      }
      obj.color = colors[gameNum]
    }
    return obj
  }

  class Player {
    avatar = doc.getElementsByClassName('head')[0].children[0].attributes.src
    grade: string
    registeredAt = parse(doc.getElementsByClassName('tooltips')[0].attributes.title, "dd MMMM yyyy, HH'h'mm", new Date(), {locale: fr})
    lastConnection = parse(doc.getElementsByClassName('tooltips')[1].attributes.title, "dd MMMM yyyy, HH'h'mm", new Date(), {locale: fr})
    banned = 0
    totalCoins = parseInt(doc.getElementsByClassName('info-stats')[0].children[0].textContent.replace(/\s+/g, '').slice(0, -17))
    totalGames = parseInt(doc.getElementsByClassName('info-stats')[0].children[1].textContent.slice(0, -14))
    friends: Array<Record<string, string>> = friends
    rushRETRO = formatData('rushretro', 0)
    rushMDT = formatData('rush', 1)
    hikaBrain = formatData('hikabrain', 2)
    skyWars = formatData('skywars', 3)
    octogone = formatData('mma', 4)
    shootCraft = formatData('shootcraft', 5)
    infected = formatData('infected', 6)
    survival = formatData('survival', 7)
    blitz = formatData('blitz', 8)
    PVPSmash = formatData('pvpsmash', 9)
    landRush = formatData('landrush', 10)

    constructor() {
      if (doc.getElementsByClassName('playername')[0].children.length > 2) {
        this.grade = ''
        for (let i = 0; i < doc.getElementsByClassName('playername')[0].children.length - 1; i++) this.grade += doc.getElementsByClassName('playername')[0].children[i].textContent
      } else this.grade = doc.getElementsByClassName('playername')[0].children[0].textContent.trim().split(' ')[0]
      if (doc.querySelector('.player-alert')! !== null)
        if (doc.querySelector('.player-alert')!.textContent.includes('temporairement')) this.banned = 1
        else this.banned = 2
    }

    get totalGlory() {
      return <number>(this.rushRETRO.glory || 0) + <number>(this.rushMDT.glory || 0) + <number>(this.hikaBrain.glory || 0) + <number>(this.skyWars.glory || 0) + <number>(this.octogone.glory || 0) + <number>(this.shootCraft.glory || 0) + <number>(this.infected.glory || 0) + <number>(this.survival.glory || 0) + <number>(this.blitz.glory || 0) + <number>(this.PVPSmash.glory || 0) + <number>(this.landRush.glory || 0)
    }

    get totalGamesWon() {
      return <number>(this.rushRETRO.gamesWon || 0) + <number>(this.rushMDT.gamesWon || 0) + <number>(this.hikaBrain.gamesWon || 0) + <number>(this.skyWars.gamesWon || 0) + <number>(this.octogone.gamesWon || 0) + <number>(this.shootCraft.gamesWon || 0) + <number>(this.infected.gamesWon || 0) + <number>(this.survival.gamesWon || 0) + <number>(this.blitz.gamesWon || 0) + <number>(this.PVPSmash.gamesWon || 0) + <number>(this.landRush.gamesWon || 0)
    }

    get totalGamesLost() {
      return <number>(this.rushRETRO.gamesLost || 0) + <number>(this.rushMDT.gamesLost || 0) + <number>(this.hikaBrain.gamesLost || 0) + <number>(this.skyWars.gamesLost || 0) + <number>(this.octogone.gamesLost || 0) + <number>(this.shootCraft.gamesLost || 0) + <number>(this.infected.gamesLost || 0) + <number>(this.survival.gamesLost || 0) + <number>(this.blitz.gamesLost || 0) + <number>(this.PVPSmash.gamesLost || 0) + <number>(this.landRush.gamesLost || 0)
    }

    get totalPlayTime() {
      return <number>(this.rushRETRO.playTime || 0) + <number>(this.rushMDT.playTime || 0) + <number>(this.hikaBrain.playTime || 0) + <number>(this.skyWars.playTime || 0) + <number>(this.octogone.playTime || 0) + <number>(this.shootCraft.playTime || 0) + <number>(this.infected.playTime || 0) + <number>(this.survival.playTime || 0) + <number>(this.blitz.playTime || 0) + <number>(this.PVPSmash.playTime || 0) + <number>(this.landRush.playTime || 0)
    }

    get totalKills() {
      return <number>(this.rushRETRO.kills || 0) + <number>(this.rushMDT.kills || 0) + <number>(this.hikaBrain.kills || 0) + <number>(this.skyWars.kills || 0) + <number>(this.octogone.kills || 0) + <number>(this.shootCraft.kills || 0) + <number>(this.infected.kills || 0) + <number>(this.survival.kills || 0) + <number>(this.blitz.kills || 0) + <number>(this.PVPSmash.kills || 0) + <number>(this.landRush.kills || 0)
    }

    get totalDeaths() {
      return <number>(this.rushRETRO.deaths || 0) + <number>(this.rushMDT.deaths || 0) + <number>(this.hikaBrain.deaths || 0) + <number>(this.skyWars.deaths || 0) + <number>(this.octogone.deaths || 0) + <number>(this.shootCraft.deaths || 0) + <number>(this.infected.deaths || 0) + <number>(this.survival.deaths || 0) + <number>(this.blitz.deaths || 0) + <number>(this.PVPSmash.deaths || 0) + <number>(this.landRush.deaths || 0)
    }
  }
  return new Player()
}
