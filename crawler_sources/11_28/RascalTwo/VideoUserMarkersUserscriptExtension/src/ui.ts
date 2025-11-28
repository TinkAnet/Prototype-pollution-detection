import { NOOP, chToPx, attachEscapeHandler, delay, secondsToDHMS, applyThemedStyles, isDarkMode } from './helpers';
import { Cacheable, Collection, IPlatform, Marker } from './types';

let openDialogs = 0;

export function getDialogCount() {
	return openDialogs;
}

export function changeDialogCount(change: number) {
	openDialogs += change;
	return openDialogs;
}

/**
 * Show customizable dialog
 *
 * @param {string} buttonClass
 * @param {'alert' | 'prompt' | 'choose'} type
 * @param {string} message
 * @param {(form: HTMLFormElement) => any} sideEffect
 */
export async function dialog(
	buttonClass: string,
	type: 'alert' | 'prompt' | 'choose',
	message: string,
	sideEffect?: (form: HTMLFormElement) => any
): Promise<any> {
	return new Promise(resolve => {
		openDialogs++;

		let canceled = false;

		const form = document.createElement('form');
		form.id = 'r2_dialog';
		form.style.position = 'absolute';
		form.style.zIndex = (9000 + openDialogs).toString();
		form.style.top = '50%';
		form.style.left = '50%';
		form.style.transform = 'translate(-50%, -50%)';
		form.style.padding = '1em';
		form.style.borderRadius = '1em';
		applyThemedStyles(form.style);
		form.style.display = 'flex';
		form.style.flexDirection = 'column';
		form.style.gap = '1rem'
		form.innerHTML = message;
		const handleSubmit = (e?: Event) => {
			e?.preventDefault();
			const response = canceled ? null : generateResponse(form);
			form.remove();
			openDialogs--;
			removeEscapeHandler();
			return resolve(response);
		};
		form.addEventListener('submit', handleSubmit);

		const [generateResponse, pre, post, afterCreated]: Function[] = {
			alert: () => [
				() => true,
				() => (form.querySelector('button[type="submit"]')! as HTMLElement).focus(),
				NOOP,
				sideEffect!,
			],
			prompt: () => {
				const [type, value] = sideEffect?.(form) ?? ['input', ''];
				const input = document.createElement(type);
				input.value = value;
				if (type === 'textarea') input.setAttribute('rows', 10);

				input.addEventListener('keydown', (e: KeyboardEvent) =>
					e.key === 'Enter' && e.ctrlKey ? handleSubmit() : undefined
				);

				form.appendChild(input);
				return [
					() => input.value.trim(),
					() => input.focus(),
					() => {
						const lines: string[] = input.value.split('\n');
						const longestLine = Math.max(...lines.map(line => line.length));
						if (!longestLine) return;
						input.style.width = Math.max(input.offsetWidth, longestLine * chToPx()) + 'px';
					},
					NOOP,
				];
			},
			choose: () => {
				form.appendChild(
					Object.entries(sideEffect!(form)).reduce((fragment, [key, value]) => {
						const button = document.createElement('button');
						button.className = buttonClass;
						button.style.width = 'auto';
						button.textContent = key;
						button.value = JSON.stringify(value);
						button.addEventListener('click', () => (form.dataset.value = button.value));
						form.dataset.value = JSON.stringify(null);

						fragment.appendChild(button);
						return fragment;
					}, document.createDocumentFragment())
				);
				return [
					() => JSON.parse(form.dataset.value!),
					() => {
						form.querySelector('button[type="submit"]')!.remove();
						form.querySelector('button')!.focus();
					},
					NOOP,
					NOOP,
				];
			},
		}[type]();

		const actions = document.createElement('div');
		actions.style.flex = '1';
		actions.style.display = 'flex';
		actions.style.gap = '1rem';
		const submit = document.createElement('button');
		submit.className = buttonClass;
		submit.style.width = 'auto';
		submit.style.flex = '1';
		submit.textContent = 'OK';
		submit.type = 'submit';
		actions.appendChild(submit);

		const cancel = document.createElement('button');
		cancel.className = buttonClass;
		cancel.style.width = 'auto';
		cancel.style.flex = '1';
		cancel.textContent = 'Cancel';
		cancel.addEventListener('click', () => (canceled = true));
		actions.appendChild(cancel);
		form.appendChild(actions);

		document.body.appendChild(form);
		const removeEscapeHandler = attachEscapeHandler(
			handleSubmit,
			() => form.style.zIndex === (9000 + openDialogs).toString()
		);

		setTimeout(() => {
			pre(form);
			afterCreated?.(form);
			post(form);
		});
	});
}

export const generateMarkerList = (
	collection: Collection,
	platform: IPlatform & Cacheable,
	getCurrentTimeLive: () => Promise<number>,
	handleMarkerUpdate: (dataChanged: boolean) => Promise<void>,
	setTime: (seconds: number) => Promise<void>,
	startEditingMarker: (marker: Marker, seconds: boolean, name: boolean, e: Event) => Promise<void>,
	seekToMarker: (marker: Marker, e: Event) => Promise<void>
) => {
	function deleteMarker(marker: Marker) {
		const index = collection.markers!.findIndex(m => m.when === marker.when);
		collection.markers!.splice(index, 1);
		return handleMarkerUpdate(true);
	}

	function adjustMarkerSeconds(marker: Marker, change: number) {
		marker.when += change;
		return handleMarkerUpdate(true).then(() => marker);
	}

	let rendering = false;
	let last = { x: 0, y: 0, top: window.innerHeight / 10, left: window.innerWidth / 10 };
	const closeFuncs: (() => void)[] = [];
	const uninstallFuncs: (() => void)[] = [];

	function appendMarkerListCSS() {
		if (document.querySelector('.r2_marker_list_style')) return () => undefined;

		const style = document.createElement('style');
		style.className = 'r2_marker_list_style';
		style.appendChild(
			document.createTextNode(`
		/* Scrollbar Styles */
		.r2_marker_list::-webkit-scrollbar {
			width: 7.5px;
		}

		.r2_marker_list::-webkit-scrollbar-track {
			background: transparent;
		}

		.r2_marker_list::-webkit-scrollbar-thumb {
			background-color: rgb(24, 24, 27);
			border-radius: 7px;
			border: 1px solid rgb(239, 239, 241);
		}

		/* Resizing Styles */
		.r2_marker_list::-webkit-resizer {
			border: 3px solid white;
			background: transparent;
			cursor: nwse-resize;
		}
	`)
		);
		document.querySelector('head')!.appendChild(style);
		return () => style.remove();
	}

	const getCurrentMarkerLI = (list: HTMLUListElement) =>
		getCurrentTimeLive().then(
			now =>
				list.querySelectorAll('li')[
					(collection.markers!
						.map((c, i) => [c, i] as [Marker, number])
						.filter(([c]) => Math.floor(c.when) <= now)
						.slice(-1)[0] ?? [null, -1])[1]
				]
		);

	function renderMarkerList() {
		if (!rendering) return removeMarkerList();
		uninstallFuncs.push(appendMarkerListCSS());

		const existingList = document.querySelector<HTMLUListElement>('.r2_marker_list');
		const list = existingList || (document.createElement('ul') as HTMLUListElement);
		if (!existingList) {
			list.className = 'r2_marker_list';
			list.style.position = 'absolute';
			list.style.zIndex = (9000 + getDialogCount()).toString();
			list.style.padding = '1em';
			list.style.borderRadius = '1em';
			list.style.display = 'flex';
			list.style.gap = '0.5em';
			list.style.flexDirection = 'column';
			list.style.maxHeight = '75vh';
			list.style.maxWidth = '50vw';
			list.style.overflow = 'scroll';
			list.style.overflowX = 'auto';
			list.style.resize = 'both';
			applyThemedStyles(list.style);

			list.style.top = last.top + 'px';
			list.style.left = last.left + 'px';

			const header = document.createElement('h4');
			header.textContent = 'Marker List';
			header.style.userSelect = 'none';
			header.style.padding = '0';
			header.style.margin = '0';
			applyThemedStyles(header.style)

			let dragging = false;
			list.addEventListener('mousedown', e => {
				if (
					Math.abs(list.offsetLeft - e.clientX) >= (list.offsetWidth / 10) * 9 &&
					Math.abs(list.offsetTop - e.clientY) >= (list.offsetHeight / 10) * 9
				)
					return;

				dragging = true;
				last.x = e.clientX;
				last.y = e.clientY;
			});
			const handleMouseUp = () => {
				dragging = false;
			};
			document.body.addEventListener('mouseup', handleMouseUp);

			const handleMouseMove = (e: MouseEvent) => {
				if (!dragging) return;

				list.style.top = list.offsetTop - (last.y - e.clientY) + 'px';
				list.style.left = list.offsetLeft - (last.x - e.clientX) + 'px';
				last.x = e.clientX;
				last.y = e.clientY;
				last.top = parseInt(list.style.top);
				last.left = parseInt(list.style.left);
			};
			document.body.addEventListener('mousemove', handleMouseMove);
			list.appendChild(header);

			uninstallFuncs.push(() => {
				document.body.removeEventListener('mousemove', handleMouseMove);
				document.body.removeEventListener('mouseup', handleMouseUp);
			});

			const closeButton = document.createElement('button');
			closeButton.className = platform.getButtonClass();
			closeButton.style.width = 'auto';
			closeButton.style.float = 'right';
			closeButton.textContent = 'Close';
			closeButton.addEventListener('click', () => setMarkerList(false));

			header.appendChild(closeButton);

			uninstallFuncs.push(
				attachEscapeHandler(
					() => setMarkerList(false),
					() => list.style.zIndex === (9000 + getDialogCount()).toString()
				)
			);
		}

		collection.markers!.sort((a, b) => a.when - b.when);
		const places = secondsToDHMS(collection.markers![collection.markers!.length - 1]?.when ?? 0).split(':').length;

		function getElementMarker(e: { target: EventTarget | null }) {
			const id = (e.target! as HTMLElement).closest<HTMLElement>('[data-id]')!.dataset.id
			return collection.markers!.find(marker => marker._id === id);
		}

		const makeActive = (li: HTMLLIElement, seekTo: boolean = true) => {
			list.querySelectorAll<HTMLLIElement>('li[data-r2_active_marker="true"]').forEach(otherLi => {
				delete otherLi.dataset.r2_active_marker;
				otherLi.style.outline = '';
			});
			li.dataset.r2_active_marker = 'true';
			li.style.outline = '1px dashed ' + (isDarkMode() ? 'white' : 'black')
			li.scrollIntoView({block: "nearest", inline: "nearest"});
			if (seekTo && !platform.isLive()) return setTime(getElementMarker({ target: li })!.when);
		};

		for (const [i, marker] of collection.markers!.entries()) {
			const existingLi = list.querySelectorAll('li')[i];
			const li = existingLi || document.createElement('li');
			li.dataset.id = marker._id;
			if (!existingLi) {
				li.style.display = 'flex';
				li.style.gap = '1em';
				li.style.alignItems = 'center';
			}

			const timeContent = secondsToDHMS(marker.when, places);

			const time = li.querySelector('span') || document.createElement('span');
			if (!existingLi) {
				time.style.fontFamily = 'monospace';
				time.addEventListener('wheel', e => {
					makeActive(li);
					// Stop native scrolling
					e.preventDefault();

					return adjustMarkerSeconds(
						getElementMarker(e)!,
						Math.min(Math.max(e.deltaY, -1), 1)
					).then(marker => (!platform.isLive() ? setTime(marker.when) : undefined));
				});

				const decrease = document.createElement('button');
				decrease.className = platform.getButtonClass();
				decrease.style.width = 'auto';
				decrease.style.display = 'inline-block';
				decrease.textContent = '-';
				decrease.title = 'Subtract 1 second';
				decrease.addEventListener('click', e => {
					makeActive(li);
					adjustMarkerSeconds(getElementMarker(e)!, -1).then(marker =>
						!platform.isLive() ? setTime(marker.when) : undefined
					);
				});
				time.appendChild(decrease);

				const timeText = document.createElement('span');
				timeText.textContent = timeContent;
				if (!platform.isLive()) {
					timeText.style.cursor = 'pointer';
					timeText.addEventListener('click', e => {
						makeActive(li);
						seekToMarker(getElementMarker(e)!, e);
					});
				}
				timeText.addEventListener('contextmenu', e => {
					startEditingMarker(getElementMarker(e)!, true, false, e);
				});
				time.appendChild(timeText);

				const increase = document.createElement('button');
				increase.className = platform.getButtonClass();
				increase.style.width = 'auto';
				increase.style.display = 'inline-block';
				increase.textContent = '+';
				increase.title = 'Add 1 second';
				increase.addEventListener('click', e => {
					makeActive(li);
					adjustMarkerSeconds(getElementMarker(e)!, 1).then(marker =>
						!platform.isLive() ? setTime(marker.when) : undefined
					);
				});
				time.appendChild(increase);
				li.appendChild(time);
			} else {
				time.childNodes[1].textContent = timeContent;
			}

			const title =
				li.querySelector<HTMLElement>('span.r2_marker_title') || document.createElement('span');
			if (!existingLi) {
				title.className = 'r2_marker_title';
				title.style.flex = '1';
				title.style.textAlign = 'center';
				if (!platform.isLive()) {
					title.style.cursor = 'pointer';
					title.addEventListener('click', e => {
						makeActive(li);
						seekToMarker(getElementMarker(e)!, e);
					});
				}
				title.addEventListener('contextmenu', e =>
					startEditingMarker(getElementMarker(e)!, false, true, e)
				);
				li.appendChild(title);
			}
			title.textContent = marker.title;

			const share =
				li.querySelector<HTMLButtonElement>('button.r2_marker_share') ||
				document.createElement('button');
			if (!existingLi) {
				share.className = platform.getButtonClass();
				share.style.width = 'auto';
				share.classList.add('r2_marker_share');
				share.style.float = 'right';
				share.textContent = 'Share';
				share.addEventListener('click', async e =>
					navigator.clipboard.writeText(await platform.generateMarkerURL(getElementMarker(e)!.when))
				);
				li.appendChild(share);
			}

			const deleteBtn =
				li.querySelector<HTMLButtonElement>('button.r2_marker_delete') ||
				document.createElement('button');
			if (!existingLi) {
				deleteBtn.className = platform.getButtonClass();
				deleteBtn.style.width = 'auto';
				deleteBtn.classList.add('r2_marker_delete');
				deleteBtn.style.float = 'right';
				deleteBtn.textContent = 'Delete';
				deleteBtn.addEventListener('click', e => {
					deleteMarker(getElementMarker(e)!);
					li.remove();
				});
				li.appendChild(deleteBtn);
			}

			if (!existingLi) {
				const closeButton = list.querySelector(':scope > button')
				if (closeButton) {
					list.insertBefore(li, closeButton);
				} else {
					list.appendChild(li);
				}
			}
		}

		if (!existingList) {
			const closeButton = document.createElement('button');
			closeButton.className = platform.getButtonClass();
			closeButton.style.width = 'auto';
			closeButton.style.float = 'right';
			closeButton.textContent = 'Close';
			closeButton.addEventListener('click', () => setMarkerList(false));
			list.appendChild(closeButton);

			document.body.appendChild(list);

			delay(100)
				.then(() => getCurrentMarkerLI(list))
				.then(li => {
					if (!li) return;
					li.scrollIntoView({block: "nearest", inline: "nearest"});
					makeActive(li, false);
				});
		}
	}

	function removeMarkerList() {
		document.querySelector('.r2_marker_list')?.remove();
		closeFuncs.forEach(close => close());
		closeFuncs.splice(0, closeFuncs.length);
	}

	uninstallFuncs.push(removeMarkerList);

	const setMarkerList = (render: boolean) => {
		rendering = render;

		changeDialogCount(Number(render));

		renderMarkerList();
	};

	const uninstallMarkerList = (() => {
		let lastLi: HTMLLIElement | null = null;
		const interval = setInterval(() => {
			const list = document.querySelector<HTMLUListElement>('.r2_marker_list')!;
			return !list
				? null
				: getCurrentMarkerLI(list).then(li => {
						if (!li) return;

						applyThemedStyles(li.style);
						if (li === lastLi) return;
						if (lastLi) lastLi.style.backgroundColor = '';
						lastLi = li;
				  });
		}, 1000);

		uninstallFuncs.forEach(func => func());
		return () => clearInterval(interval);
	})();

	return {
		removeMarkerList,
		renderMarkerList,
		setMarkerList,
		uninstallMarkerList,
	};
};
