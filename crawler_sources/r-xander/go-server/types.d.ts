declare class SortablePlugin {}
declare class AutoScrollPlugin {}
declare class OnSpillPlugin {}
declare class MultiDragPlugin {}
declare class SwapPlugin {}

export interface AutoScrollOptions {
    /**
     *  Enable the plugin. Can be `HTMLElement`.
     */
    scroll?: boolean | HTMLElement | undefined;
    /**
     * force the autoscroll fallback to kick in
     */
    forceAutoScrollFallback?: boolean | undefined;
    /**
     * if you have custom scrollbar scrollFn may be used for autoscrolling.
     */
    scrollFn?:
        | ((
              this: Sortable,
              offsetX: number,
              offsetY: number,
              originalEvent: Event,
              touchEvt: TouchEvent,
              hoverTargetEl: HTMLElement
              // eslint-disable-next-line @typescript-eslint/no-invalid-void-type
          ) => "continue" | void)
        | undefined;
    /**
     * `px`, how near the mouse must be to an edge to start scrolling.
     */
    scrollSensitivity?: number | undefined;
    /**
     * `px`, speed of the scrolling.`
     */
    scrollSpeed?: number | undefined;
    /**
     * apply autoscroll to all parent elements, allowing for easier movement.
     */
    bubbleScroll?: boolean | undefined;
}
export interface OnSpillOptions {
    /**
     * This plugin, when enabled,
     * will cause the dragged item to be reverted to it's original position if it is *spilled*
     * (ie. it is dropped outside of a valid Sortable drop target)
     */
    revertOnSpill?: boolean | undefined;
    /**
     * This plugin, when enabled,
     * will cause the dragged item to be removed from the DOM if it is *spilled*
     * (ie. it is dropped outside of a valid Sortable drop target)
     */
    removeOnSpill?: boolean | undefined;
    /**
     * Called when either `revertOnSpill` or `RemoveOnSpill` plugins are enabled.
     */
    onSpill?: ((evt: SortableEvent) => void) | undefined;
}
export interface MultiDragOptions {
    /**
     * Enable the plugin
     */
    multiDrag?: boolean | undefined;
    /**
     * Class name for selected item
     */
    selectedClass?: string | undefined;
    /**
     * The key that must be down for multiple items to be selected.
     * The default is null, meaning no key must be down.
     * For special keys, such as the CTRL key,
     * simply specify the option as 'CTRL' (casing does not matter).
     */
    multiDragKey?: null | undefined | string;

    /**
     * If you don't want to deselect items on outside click
     */
    avoidImplicitDeselect?: boolean | undefined;

    /**
     * Called when an item is selected
     */
    onSelect?: ((event: SortableEvent) => void) | undefined;

    /**
     * Called when an item is deselected
     */
    onDeselect?: ((event: SortableEvent) => void) | undefined;
}

export interface SwapOptions {
    /**
     * Enable swap mode
     */
    swap?: boolean | undefined;
    /**
     * Class name for swap item (if swap mode is enabled)
     */
    swapClass?: string | undefined;
}

export declare class Sortable {
    public options: Sortable.Options;
    public el: HTMLElement;

    /**
     * Sortable's main constructor.
     * @param element Any variety of HTMLElement.
     * @param options Sortable options object.
     */
    constructor(element: HTMLElement, options: Sortable.Options);

    static active: Sortable | null;
    static utils: Sortable.Utils;

    /**
     * Mounts a plugin to Sortable
     * @param sortablePlugin a sortable plugin.
     *
     * @example
     *
     * Sortable.mount(new MultiDrag(), new AutoScroll())
     */
    static mount(...sortablePlugins: SortablePlugin[]): void;

    /**
     * Creation of new instances.
     * @param element Any variety of HTMLElement.
     * @param options Sortable options object.
     */
    static create(element: HTMLElement, options?: Sortable.Options): Sortable;

    /** The element being dragged. */
    static dragged: HTMLElement | null;

    /** The ghost element.*/
    static ghost: HTMLElement | null;

    /** The clone element. */
    static clone: HTMLElement | null;

    /** Get the Sortable instance on an element. */
    static get(element: HTMLElement): Sortable | undefined;

    /** Get the Sortable version */
    static readonly version: string;

    /**
     * Options getter/setter
     * @param name a Sortable.Options property.
     * @param value a value.
     */
    option<K extends keyof Sortable.Options>(name: K, value: Sortable.Options[K]): void;
    option<K extends keyof Sortable.Options>(name: K): Sortable.Options[K];

    /**
     * For each element in the set, get the first element that matches the selector by testing the element itself and traversing up through its ancestors in the DOM tree.
     * @param element an HTMLElement or selector string.
     * @param selector default: `options.draggable`
     */
    closest(element: HTMLElement, selector?: string): HTMLElement | null;

    /**
     * Sorts the elements according to the array.
     * @param order an array of strings to sort.
     * @param useAnimation default: false.
     */
    sort(order: readonly string[], useAnimation?: boolean): void;

    /**
     * Saving and restoring of the sort.
     */
    save(): void;

    /**
     * Removes the sortable functionality completely.
     */
    destroy(): void;

    /**
     * Serializes the sortable's item data-id's (dataIdAttr option) into an array of string.
     */
    toArray(): string[];
}

declare namespace Sortable {
    export interface Options extends SortableOptions, AutoScrollOptions, MultiDragOptions, OnSpillOptions, SwapOptions {}

    /**
     * A class that all plugins inherit from for the sake of type inference.
     */
    export class Plugin extends SortablePlugin {}
    export class MultiDrag extends MultiDragPlugin {}
    export class AutoScroll extends AutoScrollPlugin {}
    export class Swap extends SwapPlugin {}
    export class OnSpill extends OnSpillPlugin {}

    export interface SortableEvent extends Event {
        clone: HTMLElement;
        /**
         * previous list
         */
        from: HTMLElement;
        /**
         * dragged element
         */
        item: HTMLElement;
        /**
         * dragged elements
         */
        items: HTMLElement[];
        /**
         * new index within parent
         */
        newIndex: number | undefined;
        /**
         * old index within parent
         */
        oldIndex: number | undefined;
        /**
         * the original event
         */
        originalEvent: DragEvent;
        target: HTMLElement;
        /**
         * list, in which moved element.
         */
        to: HTMLElement;
        /**
         * Old index within parent, only counting draggable elements
         */
        oldDraggableIndex: number | undefined;
        /**
         * New index within parent, only counting draggable elements
         */
        newDraggableIndex: number | undefined;
        /**
         * Pull mode if dragging into another sortable
         */
        pullMode: "clone" | boolean | undefined;
        /**
         * When MultiDrag is used to sort, this holds a HTMLElement and oldIndex for each item selected.
         *
         * `oldIndicies[number]` is directly related to `newIndicies[number]`
         *
         * If MultiDrag is not used to sort, this array will be empty.
         */
        oldIndicies: Array<{ multiDragElement: HTMLElement; index: number }>;
        /**
         * When MultiDrag is used to sort, this holds a HTMLElement and newIndex for each item.
         *
         * `oldIndicies[number]` is directly related to `newIndicies[number]`
         *
         * If MultiDrag is not used to sort, this array will be empty.
         */
        newIndicies: Array<{ multiDragElement: HTMLElement; index: number }>;
        /** When Swap is used to sort, this will contain the dragging item that was dropped on.*/
        swapItem: HTMLElement | null;
    }

    export interface MoveEvent extends Event {
        dragged: HTMLElement;
        draggedRect: DOMRect;
        from: HTMLElement;
        /**
         * element on which have guided
         */
        related: HTMLElement;
        relatedRect: DOMRect;
        to: HTMLElement;
        willInsertAfter?: boolean | undefined;
    }

    type PullResult = readonly string[] | boolean | "clone";
    type PutResult = readonly string[] | boolean;
    export interface GroupOptions {
        /**
         * group name
         */
        name: string;
        /**
         * ability to move from the list. clone — copy the item, rather than move.
         */
        pull?: PullResult | ((to: Sortable, from: Sortable, dragEl: HTMLElement, event: SortableEvent) => PullResult) | undefined;
        /**
         * whether elements can be added from other lists, or an array of group names from which elements can be taken.
         */
        put?: PutResult | ((to: Sortable, from: Sortable, dragEl: HTMLElement, event: SortableEvent) => PutResult) | undefined;
        /**
         * a canonical version of pull, created by Sortable
         */
        checkPull?:
            | ((sortable: Sortable, activeSortable: Sortable, dragEl: HTMLElement, event: SortableEvent) => boolean | string | string[])
            | undefined;
        /**
         * a canonical version of put, created by Sortable
         */
        checkPut?:
            | ((
                  sortable: Sortable,
                  activeSortable: Sortable,
                  dragEl: HTMLElement,
                  event: SortableEvent
              ) => boolean | string | "clone" | string[])
            | undefined;
        /**
         * revert cloned element to initial position after moving to a another list.
         */
        revertClone?: boolean | undefined;
    }
    type Direction = "vertical" | "horizontal";
    export interface SortableOptions {
        /**
         * ms, animation speed moving items when sorting, `0` — without animation
         */
        animation?: number | undefined;
        /**
         * Class name for the chosen item
         */
        chosenClass?: string | undefined;
        dataIdAttr?: string | undefined;
        /**
         * time in milliseconds to define when the sorting should start
         */
        delay?: number | undefined;
        /**
         * Only delay if user is using touch
         */
        delayOnTouchOnly?: boolean | undefined;
        /**
         * Direction of Sortable
         * (will be detected automatically if not given)
         */
        direction?: ((evt: SortableEvent, target: HTMLElement, dragEl: HTMLElement) => Direction) | Direction | undefined;
        /**
         * Disables the sortable if set to true.
         */
        disabled?: boolean | undefined;
        /**
         * Class name for the dragging item
         */
        dragClass?: string | undefined;
        /**
         * Specifies which items inside the element should be draggable
         */
        draggable?: string | undefined;
        dragoverBubble?: boolean | undefined;
        dropBubble?: boolean | undefined;
        /**
         * distance mouse must be from empty sortable
         * to insert drag element into it
         */
        emptyInsertThreshold?: number | undefined;

        /**
         * Easing for animation. Defaults to null.
         *
         * See https://easings.net/ for examples.
         *
         * For other possible values, see
         * https://www.w3schools.com/cssref/css3_pr_animation-timing-function.asp
         *
         * @example
         *
         * // CSS functions
         * | 'steps(int, start | end)'
         * | 'cubic-bezier(n, n, n, n)'
         *
         * // CSS values
         * | 'linear'
         * | 'ease'
         * | 'ease-in'
         * | 'ease-out'
         * | 'ease-in-out'
         * | 'step-start'
         * | 'step-end'
         * | 'initial'
         * | 'inherit'
         */
        easing?: string | undefined;
        /**
         * Class name for the cloned DOM Element when using forceFallback
         */
        fallbackClass?: string | undefined;
        /**
         * Appends the cloned DOM Element into the Document's Body
         */
        fallbackOnBody?: boolean | undefined;
        /**
         * Specify in pixels how far the mouse should move before it's considered as a drag.
         */
        fallbackTolerance?: number | undefined;
        fallbackOffset?: { x: number; y: number } | undefined;
        /**
         * Selectors that do not lead to dragging (String or Function)
         */
        filter?: string | ((this: Sortable, event: Event | TouchEvent, target: HTMLElement, sortable: Sortable) => boolean) | undefined;
        /**
         * ignore the HTML5 DnD behaviour and force the fallback to kick in
         */
        forceFallback?: boolean | undefined;
        /**
         * Class name for the drop placeholder
         */
        ghostClass?: string | undefined;
        /**
         * To drag elements from one list into another, both lists must have the same group value.
         * You can also define whether lists can give away, give and keep a copy (clone), and receive elements.
         */
        group?: string | GroupOptions | undefined;
        /**
         * Drag handle selector within list items
         */
        handle?: string | undefined;
        ignore?: string | undefined;
        /**
         * Will always use inverted swap zone if set to true
         */
        invertSwap?: boolean | undefined;
        /**
         * Threshold of the inverted swap zone
         * (will be set to `swapThreshold` value by default)
         */
        invertedSwapThreshold?: number | undefined;
        /**
         * Call `event.preventDefault()` when triggered `filter`
         */
        preventOnFilter?: boolean | undefined;
        /**
         * Remove the clone element when it is not showing,
         * rather than just hiding it
         */
        removeCloneOnHide?: boolean | undefined;
        /**
         * sorting inside list
         */
        sort?: boolean | undefined;
        store?:
            | {
                  get: (sortable: Sortable) => string[];
                  set: (sortable: Sortable) => void;
              }
            | undefined;
        /**
         * support pointer events
         */
        supportPointer?: boolean | undefined;
        /**
         * Threshold of the swap zone.
         * Defaults to `1`
         */
        swapThreshold?: number | undefined;
        /**
         * How many *pixels* the point should move before cancelling a delayed drag event
         */
        touchStartThreshold?: number | undefined;

        setData?: ((dataTransfer: DataTransfer, draggedElement: HTMLElement) => void) | undefined;
        /**
         * Element dragging started
         */
        onStart?: ((event: SortableEvent) => void) | undefined;
        /**
         * Element dragging ended
         */
        onEnd?: ((event: SortableEvent) => void) | undefined;
        /**
         * Element is dropped into the list from another list
         */
        onAdd?: ((event: SortableEvent) => void) | undefined;
        /**
         * Created a clone of an element
         */
        onClone?: ((event: SortableEvent) => void) | undefined;
        /**
         * Element is chosen
         */
        onChoose?: ((event: SortableEvent) => void) | undefined;
        /**
         * Element is unchosen
         */
        onUnchoose?: ((event: SortableEvent) => void) | undefined;
        /**
         * Changed sorting within list
         */
        onUpdate?: ((event: SortableEvent) => void) | undefined;
        /**
         * Called by any change to the list (add / update / remove)
         */
        onSort?: ((event: SortableEvent) => void) | undefined;
        /**
         * Element is removed from the list into another list
         */
        onRemove?: ((event: SortableEvent) => void) | undefined;
        /**
         * Attempt to drag a filtered element
         */
        onFilter?: ((event: SortableEvent) => void) | undefined;
        /**
         * Event when you move an item in the list or between lists
         */
        // eslint-disable-next-line @typescript-eslint/no-invalid-void-type
        onMove?: ((evt: MoveEvent, originalEvent: Event) => boolean | -1 | 1 | void) | undefined;
        /**
         * Called when dragging element changes position
         */
        onChange?: ((evt: SortableEvent) => void) | undefined;
    }

    interface Utils {
        /**
         * Attach an event handler function
         * @param element an HTMLElement.
         * @param event an Event context.
         * @param fn
         */
        on(element: HTMLElement, event: string, fn: EventListenerOrEventListenerObject): void;

        /**
         * Remove an event handler function
         * @param element an HTMLElement.
         * @param event an Event context.
         * @param fn a callback.
         */
        off(element: HTMLElement, event: string, fn: EventListenerOrEventListenerObject): void;

        /**
         * Get the values of all the CSS properties.
         * @param element an HTMLElement.
         */
        css(element: HTMLElement): CSSStyleDeclaration;

        /**
         * Get the value of style properties.
         * @param element an HTMLElement.
         * @param prop a property key.
         */
        css<K extends keyof CSSStyleDeclaration>(element: HTMLElement, prop: K): CSSStyleDeclaration[K];

        /**
         * Set one CSS property.
         * @param element an HTMLElement.
         * @param prop a property key.
         * @param value a property value.
         */
        css<K extends keyof CSSStyleDeclaration>(element: HTMLElement, prop: K, value: CSSStyleDeclaration[K]): void;

        /**
         * Get elements by tag name.
         * @param context an HTMLElement.
         * @param tagName A tag name.
         * @param iterator An iterator.
         */
        find(context: HTMLElement, tagName: string, iterator?: (value: HTMLElement, index: number) => void): NodeListOf<HTMLElement>;

        /**
         * Check the current matched set of elements against a selector.
         * @param element an HTMLElement.
         * @param selector an element selector.
         */
        is(element: HTMLElement, selector: string): boolean;

        /**
         * For each element in the set, get the first element that matches the selector by testing the element itself and traversing up through its ancestors in the DOM tree.
         * @param element an HTMLElement.
         * @param selector an element seletor.
         * @param context a specific element's context.
         */
        closest(element: HTMLElement, selector: string, context?: HTMLElement): HTMLElement | null;

        /**
         * Add or remove one classes from each element
         * @param element an HTMLElement.
         * @param name a class name.
         * @param state a class's state.
         */
        toggleClass(element: HTMLElement, name: string, state: boolean): void;

        /**
         * Selects the provided multi-drag item
         * @param element The element to be selected
         */
        select(element: HTMLElement): void;

        /**
         * Deselects the provided multi-drag item
         * @param element The element to be deselected
         */
        deselect(element: HTMLElement): void;
    }

    interface DOMRect {
        bottom: number;
        height: number;
        left: number;
        right: number;
        top: number;
        width: number;
        x: number;
        y: number;
    }
}

/**************************************************************/
/*                                                            */
/*                                                            */
/*                                                            */
/**************************************************************/

export as namespace L;

/** A constant that represents the Leaflet version in use. */
export const version: string;

export class Class {
    static extend(props: any): { new(...args: any[]): any } & typeof Class;
    static include(props: any): any & typeof Class;
    static mergeOptions(props: any): any & typeof Class;

    static addInitHook(initHookFn: () => void): any & typeof Class;
    static addInitHook(methodName: string, ...args: any[]): any & typeof Class;

    static callInitHooks(): void;
}

export class Transformation {
    constructor(a: number, b: number, c: number, d: number);
    transform(point: Point, scale?: number): Point;
    untransform(point: Point, scale?: number): Point;
}

/** Instantiates a Transformation object with the given coefficients. */
export function transformation(a: number, b: number, c: number, d: number): Transformation;

/** Expects an coefficients array of the form `[a: Number, b: Number, c: Number, d: Number]`. */
export function transformation(coefficients: [number, number, number, number]): Transformation;

/**
 * @see https://github.com/Leaflet/Leaflet/blob/bc918d4bdc2ba189807bc207c77080fb41ecc196/src/geometry/LineUtil.js#L118
 */
export namespace LineUtil {
    function simplify(points: Point[], tolerance: number): Point[];
    function pointToSegmentDistance(p: Point, p1: Point, p2: Point): number;
    function closestPointOnSegment(p: Point, p1: Point, p2: Point): Point;
    function isFlat(latlngs: LatLngExpression[]): boolean;
    function clipSegment(
        a: Point,
        b: Point,
        bounds: Bounds,
        useLastCode?: boolean,
        round?: boolean,
    ): [Point, Point] | false;
    function polylineCenter(latlngs: LatLngExpression[], crs: CRS): LatLng;
}

export namespace PolyUtil {
    function clipPolygon(points: Point[], bounds: BoundsExpression, round?: boolean): Point[];
    function polygonCenter(latlngs: LatLngExpression[], crs: CRS): LatLng;
}

export namespace DomUtil {
    /**
     * Get Element by its ID or with the given HTML-Element
     */
    function get(element: string | HTMLElement): HTMLElement | null;
    function getStyle(el: HTMLElement, styleAttrib: string): string | null;
    /**
     * Creates an HTML element with `tagName`, sets its class to `className`, and optionally appends it to `container` element.
     * @param tagName The name of the tag to create (for example: `div` or `canvas`).
     * @param className The class to set on the created element.
     * @param container The container to append the created element to.
     */
    function create<T extends keyof HTMLElementTagNameMap>(
        tagName: T,
        className?: string,
        container?: HTMLElement,
    ): HTMLElementTagNameMap[T];
    function create(tagName: string, className?: string, container?: HTMLElement): HTMLElement;
    function remove(el: HTMLElement): void;
    function empty(el: HTMLElement): void;
    function toFront(el: HTMLElement): void;
    function toBack(el: HTMLElement): void;
    function hasClass(el: HTMLElement, name: string): boolean;
    function addClass(el: HTMLElement, name: string): void;
    function removeClass(el: HTMLElement, name: string): void;
    function setClass(el: HTMLElement, name: string): void;
    function getClass(el: HTMLElement): string;
    function setOpacity(el: HTMLElement, opacity: number): void;
    function testProp(props: string[]): string | false;
    function setTransform(el: HTMLElement, offset: Point, scale?: number): void;
    function setPosition(el: HTMLElement, position: Point): void;
    function getPosition(el: HTMLElement): Point;
    function getScale(el: HTMLElement): { x: number; y: number; boundingClientRect: DOMRect };
    function getSizedParentNode(el: HTMLElement): HTMLElement;
    function disableTextSelection(): void;
    function enableTextSelection(): void;
    function disableImageDrag(): void;
    function enableImageDrag(): void;
    function preventOutline(el: HTMLElement): void;
    function restoreOutline(): void;

    let TRANSFORM: string;
    let TRANSITION: string;
    let TRANSITION_END: string;
}

export class PosAnimation extends Evented {
    run(el: HTMLElement, newPos: Point, duration?: number, easeLinearity?: number): void;
    stop(): void;
}

export interface CRS {
    latLngToPoint(latlng: LatLngExpression, zoom: number): Point;
    pointToLatLng(point: PointExpression, zoom: number): LatLng;
    project(latlng: LatLng | LatLngLiteral): Point;
    unproject(point: PointExpression): LatLng;
    scale(zoom: number): number;
    zoom(scale: number): number;
    getProjectedBounds(zoom: number): Bounds;
    distance(latlng1: LatLngExpression, latlng2: LatLngExpression): number;
    wrapLatLng(latlng: LatLng | LatLngLiteral): LatLng;

    code?: string | undefined;
    wrapLng?: [number, number] | undefined;
    wrapLat?: [number, number] | undefined;
    infinite: boolean;
}

export namespace CRS {
    const EPSG3395: CRS;
    const EPSG3857: CRS;
    const EPSG4326: CRS;
    const EPSG900913: CRS;
    const Earth: CRS;
    const Simple: CRS;
}

export interface Projection {
    project(latlng: LatLng | LatLngLiteral): Point;
    unproject(point: PointExpression): LatLng;

    bounds: Bounds;
}

export namespace Projection {
    const LonLat: Projection;
    const Mercator: Projection;
    const SphericalMercator: Projection;
}

export class LatLng {
    constructor(latitude: number, longitude: number, altitude?: number);
    equals(otherLatLng: LatLngExpression, maxMargin?: number): boolean;
    toString(): string;
    distanceTo(otherLatLng: LatLngExpression): number;
    wrap(): LatLng;
    toBounds(sizeInMeters: number): LatLngBounds;
    clone(): LatLng;

    lat: number;
    lng: number;
    alt?: number | undefined;
}

export interface LatLngLiteral {
    lat: number;
    lng: number;
    alt?: number;
}

export type LatLngTuple = [number, number, number?];

export type LatLngExpression = LatLng | LatLngLiteral | LatLngTuple;

export function latLng(latitude: number, longitude: number, altitude?: number): LatLng;

export function latLng(
    coords: LatLngTuple | [number, number, number] | LatLngLiteral | {
        lat: number;
        lng: number;
        alt?: number | undefined;
    },
): LatLng;

export class LatLngBounds {
    constructor(southWest: LatLngExpression, northEast: LatLngExpression);
    constructor(latlngs: LatLngBoundsLiteral);
    extend(latlngOrBounds: LatLngExpression | LatLngBoundsExpression): this;
    pad(bufferRatio: number): LatLngBounds; // Returns a new LatLngBounds
    getCenter(): LatLng;
    getSouthWest(): LatLng;
    getNorthEast(): LatLng;
    getNorthWest(): LatLng;
    getSouthEast(): LatLng;
    getWest(): number;
    getSouth(): number;
    getEast(): number;
    getNorth(): number;
    contains(otherBoundsOrLatLng: LatLngBoundsExpression | LatLngExpression): boolean;
    intersects(otherBounds: LatLngBoundsExpression): boolean;
    overlaps(otherBounds: LatLngBoundsExpression): boolean;
    toBBoxString(): string;
    equals(otherBounds: LatLngBoundsExpression, maxMargin?: number): boolean;
    isValid(): boolean;
}

export type LatLngBoundsLiteral = LatLngTuple[]; // Must be [LatLngTuple, LatLngTuple], cant't change because Map.setMaxBounds

export type LatLngBoundsExpression = LatLngBounds | LatLngBoundsLiteral;

export function latLngBounds(southWest: LatLngExpression, northEast: LatLngExpression): LatLngBounds;

export function latLngBounds(latlngs: LatLngExpression[]): LatLngBounds;

export type PointTuple = [number, number];

export class Point {
    constructor(x: number, y: number, round?: boolean);
    clone(): Point;
    add(otherPoint: PointExpression): Point; // non-destructive, returns a new point
    subtract(otherPoint: PointExpression): Point;
    divideBy(num: number): Point;
    multiplyBy(num: number): Point;
    scaleBy(scale: PointExpression): Point;
    unscaleBy(scale: PointExpression): Point;
    round(): Point;
    floor(): Point;
    ceil(): Point;
    trunc(): Point;
    distanceTo(otherPoint: PointExpression): number;
    equals(otherPoint: PointExpression): boolean;
    contains(otherPoint: PointExpression): boolean;
    toString(): string;
    x: number;
    y: number;
}

export interface Coords extends Point {
    z: number;
}

export type PointExpression = Point | PointTuple;

export function point(x: number, y: number, round?: boolean): Point;

export function point(coords: PointTuple | { x: number; y: number }): Point;

export type BoundsLiteral = [PointTuple, PointTuple];

export class Bounds {
    constructor(topLeft: PointExpression, bottomRight: PointExpression);
    constructor(points?: Point[] | BoundsLiteral);

    // tslint:disable:unified-signatures
    extend(point: PointExpression): this;
    extend(otherBounds: BoundsExpression): this;
    // tslint:enable:unified-signatures

    getCenter(round?: boolean): Point;
    getBottomLeft(): Point;
    getBottomRight(): Point;
    getTopLeft(): Point;
    getTopRight(): Point;
    getSize(): Point;
    contains(pointOrBounds: BoundsExpression | PointExpression): boolean;
    intersects(otherBounds: BoundsExpression): boolean;
    overlaps(otherBounds: BoundsExpression): boolean;
    isValid(): boolean;
    pad(bufferRatio: number): Bounds; // Returns a new Bounds
    equals(otherBounds: BoundsExpression): boolean;

    min?: Point | undefined;
    max?: Point | undefined;
}

export type BoundsExpression = Bounds | BoundsLiteral;

export function bounds(topLeft: PointExpression, bottomRight: PointExpression): Bounds;

export function bounds(points: Point[] | BoundsLiteral): Bounds;

// Event handler types

export type LeafletEventHandlerFn = (event: LeafletEvent) => void;

export type LayersControlEventHandlerFn = (event: LayersControlEvent) => void;

export type LayerEventHandlerFn = (event: LayerEvent) => void;

export type ResizeEventHandlerFn = (event: ResizeEvent) => void;

export type PopupEventHandlerFn = (event: PopupEvent) => void;

export type TooltipEventHandlerFn = (event: TooltipEvent) => void;

export type ErrorEventHandlerFn = (event: ErrorEvent) => void;

export type LocationEventHandlerFn = (event: LocationEvent) => void;

export type LeafletMouseEventHandlerFn = (event: LeafletMouseEvent) => void;

export type LeafletKeyboardEventHandlerFn = (event: LeafletKeyboardEvent) => void;

export type ZoomAnimEventHandlerFn = (event: ZoomAnimEvent) => void;

export type DragEndEventHandlerFn = (event: DragEndEvent) => void;

export type TileEventHandlerFn = (event: TileEvent) => void;

export type TileErrorEventHandlerFn = (event: TileErrorEvent) => void;

export interface LeafletEventHandlerFnMap {
    baselayerchange?: LayersControlEventHandlerFn | undefined;
    overlayadd?: LayersControlEventHandlerFn | undefined;
    overlayremove?: LayersControlEventHandlerFn | undefined;

    layeradd?: LayerEventHandlerFn | undefined;
    layerremove?: LayerEventHandlerFn | undefined;

    zoomlevelschange?: LeafletEventHandlerFn | undefined;
    unload?: LeafletEventHandlerFn | undefined;
    viewreset?: LeafletEventHandlerFn | undefined;
    load?: LeafletEventHandlerFn | undefined;
    zoomstart?: LeafletEventHandlerFn | undefined;
    movestart?: LeafletEventHandlerFn | undefined;
    zoom?: LeafletEventHandlerFn | undefined;
    move?: LeafletEventHandlerFn | undefined;
    zoomend?: LeafletEventHandlerFn | undefined;
    moveend?: LeafletEventHandlerFn | undefined;
    autopanstart?: LeafletEventHandlerFn | undefined;
    dragstart?: LeafletEventHandlerFn | undefined;
    drag?: LeafletEventHandlerFn | undefined;
    add?: LeafletEventHandlerFn | undefined;
    remove?: LeafletEventHandlerFn | undefined;
    loading?: LeafletEventHandlerFn | undefined;
    error?: LeafletEventHandlerFn | undefined;
    update?: LeafletEventHandlerFn | undefined;
    down?: LeafletEventHandlerFn | undefined;
    predrag?: LeafletEventHandlerFn | undefined;

    resize?: ResizeEventHandlerFn | undefined;

    popupopen?: PopupEventHandlerFn | undefined;
    popupclose?: PopupEventHandlerFn | undefined;

    tooltipopen?: TooltipEventHandlerFn | undefined;
    tooltipclose?: TooltipEventHandlerFn | undefined;

    locationerror?: ErrorEventHandlerFn | undefined;

    locationfound?: LocationEventHandlerFn | undefined;

    click?: LeafletMouseEventHandlerFn | undefined;
    dblclick?: LeafletMouseEventHandlerFn | undefined;
    mousedown?: LeafletMouseEventHandlerFn | undefined;
    mouseup?: LeafletMouseEventHandlerFn | undefined;
    mouseover?: LeafletMouseEventHandlerFn | undefined;
    mouseout?: LeafletMouseEventHandlerFn | undefined;
    mousemove?: LeafletMouseEventHandlerFn | undefined;
    contextmenu?: LeafletMouseEventHandlerFn | undefined;
    preclick?: LeafletMouseEventHandlerFn | undefined;

    keypress?: LeafletKeyboardEventHandlerFn | undefined;
    keydown?: LeafletKeyboardEventHandlerFn | undefined;
    keyup?: LeafletKeyboardEventHandlerFn | undefined;

    zoomanim?: ZoomAnimEventHandlerFn | undefined;

    dragend?: DragEndEventHandlerFn | undefined;

    tileunload?: TileEventHandlerFn | undefined;
    tileloadstart?: TileEventHandlerFn | undefined;
    tileload?: TileEventHandlerFn | undefined;
    tileabort?: TileEventHandlerFn | undefined;

    tileerror?: TileErrorEventHandlerFn | undefined;

    // [name: string]: any;
    // You are able add additional properties, but it makes this interface uncheckable.
}

/**
 * A set of methods shared between event-powered classes (like Map and Marker).
 * Generally, events allow you to execute some function when something happens
 * with an object (e.g. the user clicks on the map, causing the map to fire
 * 'click' event).
 */
// eslint-disable-next-line @definitelytyped/strict-export-declare-modifiers
declare class Events {
    /**
     * Adds a listener function (fn) to a particular event type of the object.
     * You can optionally specify the context of the listener (object the this
     * keyword will point to). You can also pass several space-separated types
     * (e.g. 'click dblclick').
     */
    // tslint:disable:unified-signatures
    on(type: "baselayerchange" | "overlayadd" | "overlayremove", fn: LayersControlEventHandlerFn, context?: any): this;
    on(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    on(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    on(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    on(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    on(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    on(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    on(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    on(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    on(type: "keypress" | "keydown" | "keyup", fn: LeafletKeyboardEventHandlerFn, context?: any): this;
    on(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    on(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    on(type: "tileunload" | "tileloadstart" | "tileload" | "tileabort", fn: TileEventHandlerFn, context?: any): this;
    on(type: "tileerror", fn: TileErrorEventHandlerFn, context?: any): this;
    on(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Adds a set of type/listener pairs, e.g. {click: onClick, mousemove: onMouseMove}
     */
    on(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Removes a previously added listener function. If no function is specified,
     * it will remove all the listeners of that particular event from the object.
     * Note that if you passed a custom context to on, you must pass the same context
     * to off in order to remove the listener.
     */
    // tslint:disable:unified-signatures
    off(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn?: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    off(type: "layeradd" | "layerremove", fn?: LayerEventHandlerFn, context?: any): this;
    off(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn?: LeafletEventHandlerFn,
        context?: any,
    ): this;
    off(type: "resize", fn?: ResizeEventHandlerFn, context?: any): this;
    off(type: "popupopen" | "popupclose", fn?: PopupEventHandlerFn, context?: any): this;
    off(type: "tooltipopen" | "tooltipclose", fn?: TooltipEventHandlerFn, context?: any): this;
    off(type: "locationerror", fn?: ErrorEventHandlerFn, context?: any): this;
    off(type: "locationfound", fn?: LocationEventHandlerFn, context?: any): this;
    off(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn?: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    off(type: "keypress" | "keydown" | "keyup", fn?: LeafletKeyboardEventHandlerFn, context?: any): this;
    off(type: "zoomanim", fn?: ZoomAnimEventHandlerFn, context?: any): this;
    off(type: "dragend", fn?: DragEndEventHandlerFn, context?: any): this;
    off(type: "tileunload" | "tileloadstart" | "tileload" | "tileabort", fn?: TileEventHandlerFn, context?: any): this;
    off(type: "tileerror", fn?: TileErrorEventHandlerFn, context?: any): this;
    off(type: string, fn?: LeafletEventHandlerFn, context?: any): this;

    /**
     * Removes a set of type/listener pairs.
     */
    // With an eventMap there are no additional arguments allowed
    off(eventMap: LeafletEventHandlerFnMap): this;

    /**
     * Removes all listeners to all events on the object.
     */
    off(): this;
    // tslint:enable:unified-signatures

    /**
     * Fires an event of the specified type. You can optionally provide a data
     * object — the first argument of the listener function will contain its properties.
     * The event might can optionally be propagated to event parents.
     */
    fire(type: string, data?: any, propagate?: boolean): this;

    /**
     * Returns true if a particular event type has any listeners attached to it.
     */
    // tslint:disable:unified-signatures
    listens(
        type:
            | "baselayerchange"
            | "overlayadd"
            | "overlayremove"
            | "layeradd"
            | "layerremove"
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag"
            | "resize"
            | "popupopen"
            | "tooltipopen"
            | "tooltipclose"
            | "locationerror"
            | "locationfound"
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick"
            | "keypress"
            | "keydown"
            | "keyup"
            | "zoomanim"
            | "dragend"
            | "tileunload"
            | "tileloadstart"
            | "tileload"
            | "tileabort"
            | "tileerror",
        propagate?: boolean,
    ): boolean;

    listens(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "resize", fn: ResizeEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type: "tooltipopen" | "tooltipclose",
        fn: TooltipEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "locationerror", fn: ErrorEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: "locationfound", fn: LocationEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(
        type: "keypress" | "keydown" | "keyup",
        fn: LeafletKeyboardEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: "dragend", fn: DragEndEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn: TileEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "tileerror", fn: TileEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: string, fn: LeafletEventHandlerFn, context?: any, propagate?: boolean): boolean;

    /**
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    // tslint:disable:unified-signatures
    once(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    once(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    once(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    once(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    once(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    once(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    once(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    once(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    once(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    once(type: "keypress" | "keydown" | "keyup", fn: LeafletKeyboardEventHandlerFn, context?: any): this;
    once(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    once(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    once(type: "tileunload" | "tileloadstart" | "tileload" | "tileabort", fn: TileEventHandlerFn, context?: any): this;
    once(type: "tileerror", fn: TileEventHandlerFn, context?: any): this;
    once(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    once(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Adds an event parent - an Evented that will receive propagated events
     */
    addEventParent(obj: Evented): this;

    /**
     * Removes an event parent, so it will stop receiving propagated events
     */
    removeEventParent(obj: Evented): this;

    /**
     * Alias for on(...)
     *
     * Adds a listener function (fn) to a particular event type of the object.
     * You can optionally specify the context of the listener (object the this
     * keyword will point to). You can also pass several space-separated types
     * (e.g. 'click dblclick').
     */
    // tslint:disable:unified-signatures
    addEventListener(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    addEventListener(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    addEventListener(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    addEventListener(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    addEventListener(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    addEventListener(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    addEventListener(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "keypress" | "keydown" | "keyup", fn: LeafletKeyboardEventHandlerFn, context?: any): this;
    addEventListener(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    addEventListener(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    addEventListener(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn: TileEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "tileerror", fn: TileErrorEventHandlerFn, context?: any): this;
    addEventListener(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Alias for on(...)
     *
     * Adds a set of type/listener pairs, e.g. {click: onClick, mousemove: onMouseMove}
     */
    addEventListener(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Alias for off(...)
     *
     * Removes a previously added listener function. If no function is specified,
     * it will remove all the listeners of that particular event from the object.
     * Note that if you passed a custom context to on, you must pass the same context
     * to off in order to remove the listener.
     */
    // tslint:disable:unified-signatures
    removeEventListener(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn?: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "layeradd" | "layerremove", fn?: LayerEventHandlerFn, context?: any): this;
    removeEventListener(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn?: LeafletEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "resize", fn?: ResizeEventHandlerFn, context?: any): this;
    removeEventListener(type: "popupopen" | "popupclose", fn?: PopupEventHandlerFn, context?: any): this;
    removeEventListener(type: "tooltipopen" | "tooltipclose", fn?: TooltipEventHandlerFn, context?: any): this;
    removeEventListener(type: "locationerror", fn?: ErrorEventHandlerFn, context?: any): this;
    removeEventListener(type: "locationfound", fn?: LocationEventHandlerFn, context?: any): this;
    removeEventListener(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn?: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(
        type: "keypress" | "keydown" | "keyup",
        fn?: LeafletKeyboardEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "zoomanim", fn?: ZoomAnimEventHandlerFn, context?: any): this;
    removeEventListener(type: "dragend", fn?: DragEndEventHandlerFn, context?: any): this;
    removeEventListener(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn?: TileEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "tileerror", fn?: TileErrorEventHandlerFn, context?: any): this;
    removeEventListener(type: string, fn?: LeafletEventHandlerFn, context?: any): this;

    /**
     * Alias for off(...)
     *
     * Removes a set of type/listener pairs.
     */
    removeEventListener(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Alias for off()
     *
     * Removes all listeners to all events on the object.
     */
    clearAllEventListeners(): this;

    /**
     * Alias for once(...)
     *
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    // tslint:disable:unified-signatures
    addOneTimeEventListener(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    addOneTimeEventListener(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    addOneTimeEventListener(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(
        type: "keypress" | "keydown" | "keyup",
        fn: LeafletKeyboardEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    addOneTimeEventListener(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn: TileEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "tileerror", fn: TileErrorEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Alias for once(...)
     *
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    addOneTimeEventListener(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Alias for fire(...)
     *
     * Fires an event of the specified type. You can optionally provide a data
     * object — the first argument of the listener function will contain its properties.
     * The event might can optionally be propagated to event parents.
     */
    fireEvent(type: string, data?: any, propagate?: boolean): this;

    /**
     * Alias for listens(...)
     *
     * Returns true if a particular event type has any listeners attached to it.
     */
    hasEventListeners(type: string): boolean;
}

// eslint-disable-next-line @definitelytyped/strict-export-declare-modifiers
declare class MixinType {
    Events: Events;
}

export const Mixin: MixinType;

/**
 * Base class of Leaflet classes supporting events
 */
export abstract class Evented extends Class {
    /**
     * Adds a listener function (fn) to a particular event type of the object.
     * You can optionally specify the context of the listener (object the this
     * keyword will point to). You can also pass several space-separated types
     * (e.g. 'click dblclick').
     */
    // tslint:disable:unified-signatures
    on(type: "baselayerchange" | "overlayadd" | "overlayremove", fn: LayersControlEventHandlerFn, context?: any): this;
    on(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    on(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    on(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    on(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    on(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    on(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    on(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    on(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    on(type: "keypress" | "keydown" | "keyup", fn: LeafletKeyboardEventHandlerFn, context?: any): this;
    on(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    on(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    on(type: "tileunload" | "tileloadstart" | "tileload" | "tileabort", fn: TileEventHandlerFn, context?: any): this;
    on(type: "tileerror", fn: TileErrorEventHandlerFn, context?: any): this;
    on(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Adds a set of type/listener pairs, e.g. {click: onClick, mousemove: onMouseMove}
     */
    on(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Removes a previously added listener function. If no function is specified,
     * it will remove all the listeners of that particular event from the object.
     * Note that if you passed a custom context to on, you must pass the same context
     * to off in order to remove the listener.
     */
    // tslint:disable:unified-signatures
    off(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn?: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    off(type: "layeradd" | "layerremove", fn?: LayerEventHandlerFn, context?: any): this;
    off(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn?: LeafletEventHandlerFn,
        context?: any,
    ): this;
    off(type: "resize", fn?: ResizeEventHandlerFn, context?: any): this;
    off(type: "popupopen" | "popupclose", fn?: PopupEventHandlerFn, context?: any): this;
    off(type: "tooltipopen" | "tooltipclose", fn?: TooltipEventHandlerFn, context?: any): this;
    off(type: "locationerror", fn?: ErrorEventHandlerFn, context?: any): this;
    off(type: "locationfound", fn?: LocationEventHandlerFn, context?: any): this;
    off(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn?: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    off(type: "keypress" | "keydown" | "keyup", fn?: LeafletKeyboardEventHandlerFn, context?: any): this;
    off(type: "zoomanim", fn?: ZoomAnimEventHandlerFn, context?: any): this;
    off(type: "dragend", fn?: DragEndEventHandlerFn, context?: any): this;
    off(type: "tileunload" | "tileloadstart" | "tileload" | "tileabort", fn?: TileEventHandlerFn, context?: any): this;
    off(type: "tileerror", fn?: TileErrorEventHandlerFn, context?: any): this;
    off(type: string, fn?: LeafletEventHandlerFn, context?: any): this;

    /**
     * Removes a set of type/listener pairs.
     */
    // With an eventMap there are no additional arguments allowed
    off(eventMap: LeafletEventHandlerFnMap): this;

    /**
     * Removes all listeners to all events on the object.
     */
    off(): this;
    // tslint:enable:unified-signatures

    /**
     * Fires an event of the specified type. You can optionally provide a data
     * object — the first argument of the listener function will contain its properties.
     * The event might can optionally be propagated to event parents.
     */
    fire(type: string, data?: any, propagate?: boolean): this;

    /**
     * Returns true if a particular event type has any listeners attached to it.
     */
    // tslint:disable:unified-signatures
    listens(
        type:
            | "baselayerchange"
            | "overlayadd"
            | "overlayremove"
            | "layeradd"
            | "layerremove"
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag"
            | "resize"
            | "popupopen"
            | "tooltipopen"
            | "tooltipclose"
            | "locationerror"
            | "locationfound"
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick"
            | "keypress"
            | "keydown"
            | "keyup"
            | "zoomanim"
            | "dragend"
            | "tileunload"
            | "tileloadstart"
            | "tileload"
            | "tileabort"
            | "tileerror",
        propagate?: boolean,
    ): boolean;

    listens(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "resize", fn: ResizeEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type: "tooltipopen" | "tooltipclose",
        fn: TooltipEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "locationerror", fn: ErrorEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: "locationfound", fn: LocationEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(
        type: "keypress" | "keydown" | "keyup",
        fn: LeafletKeyboardEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: "dragend", fn: DragEndEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn: TileEventHandlerFn,
        context?: any,
        propagate?: boolean,
    ): boolean;
    listens(type: "tileerror", fn: TileEventHandlerFn, context?: any, propagate?: boolean): boolean;
    listens(type: string, fn: LeafletEventHandlerFn, context?: any, propagate?: boolean): boolean;

    /**
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    // tslint:disable:unified-signatures
    once(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    once(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    once(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    once(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    once(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    once(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    once(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    once(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    once(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    once(type: "keypress" | "keydown" | "keyup", fn: LeafletKeyboardEventHandlerFn, context?: any): this;
    once(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    once(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    once(type: "tileunload" | "tileloadstart" | "tileload" | "tileabort", fn: TileEventHandlerFn, context?: any): this;
    once(type: "tileerror", fn: TileEventHandlerFn, context?: any): this;
    once(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    once(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Adds an event parent - an Evented that will receive propagated events
     */
    addEventParent(obj: Evented): this;

    /**
     * Removes an event parent, so it will stop receiving propagated events
     */
    removeEventParent(obj: Evented): this;

    /**
     * Alias for on(...)
     *
     * Adds a listener function (fn) to a particular event type of the object.
     * You can optionally specify the context of the listener (object the this
     * keyword will point to). You can also pass several space-separated types
     * (e.g. 'click dblclick').
     */
    // tslint:disable:unified-signatures
    addEventListener(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    addEventListener(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    addEventListener(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    addEventListener(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    addEventListener(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    addEventListener(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    addEventListener(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "keypress" | "keydown" | "keyup", fn: LeafletKeyboardEventHandlerFn, context?: any): this;
    addEventListener(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    addEventListener(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    addEventListener(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn: TileEventHandlerFn,
        context?: any,
    ): this;
    addEventListener(type: "tileerror", fn: TileErrorEventHandlerFn, context?: any): this;
    addEventListener(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Alias for on(...)
     *
     * Adds a set of type/listener pairs, e.g. {click: onClick, mousemove: onMouseMove}
     */
    addEventListener(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Alias for off(...)
     *
     * Removes a previously added listener function. If no function is specified,
     * it will remove all the listeners of that particular event from the object.
     * Note that if you passed a custom context to on, you must pass the same context
     * to off in order to remove the listener.
     */
    // tslint:disable:unified-signatures
    removeEventListener(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn?: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "layeradd" | "layerremove", fn?: LayerEventHandlerFn, context?: any): this;
    removeEventListener(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn?: LeafletEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "resize", fn?: ResizeEventHandlerFn, context?: any): this;
    removeEventListener(type: "popupopen" | "popupclose", fn?: PopupEventHandlerFn, context?: any): this;
    removeEventListener(type: "tooltipopen" | "tooltipclose", fn?: TooltipEventHandlerFn, context?: any): this;
    removeEventListener(type: "locationerror", fn?: ErrorEventHandlerFn, context?: any): this;
    removeEventListener(type: "locationfound", fn?: LocationEventHandlerFn, context?: any): this;
    removeEventListener(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn?: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(
        type: "keypress" | "keydown" | "keyup",
        fn?: LeafletKeyboardEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "zoomanim", fn?: ZoomAnimEventHandlerFn, context?: any): this;
    removeEventListener(type: "dragend", fn?: DragEndEventHandlerFn, context?: any): this;
    removeEventListener(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn?: TileEventHandlerFn,
        context?: any,
    ): this;
    removeEventListener(type: "tileerror", fn?: TileErrorEventHandlerFn, context?: any): this;
    removeEventListener(type: string, fn?: LeafletEventHandlerFn, context?: any): this;

    /**
     * Alias for off(...)
     *
     * Removes a set of type/listener pairs.
     */
    removeEventListener(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Alias for off()
     *
     * Removes all listeners to all events on the object.
     */
    clearAllEventListeners(): this;

    /**
     * Alias for once(...)
     *
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    // tslint:disable:unified-signatures
    addOneTimeEventListener(
        type: "baselayerchange" | "overlayadd" | "overlayremove",
        fn: LayersControlEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "layeradd" | "layerremove", fn: LayerEventHandlerFn, context?: any): this;
    addOneTimeEventListener(
        type:
            | "zoomlevelschange"
            | "unload"
            | "viewreset"
            | "load"
            | "zoomstart"
            | "movestart"
            | "zoom"
            | "move"
            | "zoomend"
            | "moveend"
            | "autopanstart"
            | "dragstart"
            | "drag"
            | "add"
            | "remove"
            | "loading"
            | "error"
            | "update"
            | "down"
            | "predrag",
        fn: LeafletEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "resize", fn: ResizeEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "popupopen" | "popupclose", fn: PopupEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "tooltipopen" | "tooltipclose", fn: TooltipEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "locationerror", fn: ErrorEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "locationfound", fn: LocationEventHandlerFn, context?: any): this;
    addOneTimeEventListener(
        type:
            | "click"
            | "dblclick"
            | "mousedown"
            | "mouseup"
            | "mouseover"
            | "mouseout"
            | "mousemove"
            | "contextmenu"
            | "preclick",
        fn: LeafletMouseEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(
        type: "keypress" | "keydown" | "keyup",
        fn: LeafletKeyboardEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "zoomanim", fn: ZoomAnimEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: "dragend", fn: DragEndEventHandlerFn, context?: any): this;
    addOneTimeEventListener(
        type: "tileunload" | "tileloadstart" | "tileload" | "tileabort",
        fn: TileEventHandlerFn,
        context?: any,
    ): this;
    addOneTimeEventListener(type: "tileerror", fn: TileErrorEventHandlerFn, context?: any): this;
    addOneTimeEventListener(type: string, fn: LeafletEventHandlerFn, context?: any): this;

    /**
     * Alias for once(...)
     *
     * Behaves as on(...), except the listener will only get fired once and then removed.
     */
    addOneTimeEventListener(eventMap: LeafletEventHandlerFnMap): this;
    // tslint:enable:unified-signatures

    /**
     * Alias for fire(...)
     *
     * Fires an event of the specified type. You can optionally provide a data
     * object — the first argument of the listener function will contain its properties.
     * The event might can optionally be propagated to event parents.
     */
    fireEvent(type: string, data?: any, propagate?: boolean): this;

    /**
     * Alias for listens(...)
     *
     * Returns true if a particular event type has any listeners attached to it.
     */
    hasEventListeners(type: string): boolean;
}

export interface DraggableOptions {
    /**
     * The max number of pixels a user can shift the mouse pointer during a click
     * for it to be considered a valid click (as opposed to a mouse drag).
     */
    clickTolerance: number;
}

/**
 * A class for making DOM elements draggable (including touch support).
 * Used internally for map and marker dragging. Only works for elements
 * that were positioned with [`L.DomUtil.setPosition`](#domutil-setposition).
 */
export class Draggable extends Evented {
    constructor(
        element: HTMLElement,
        dragStartTarget?: HTMLElement,
        preventOutline?: boolean,
        options?: DraggableOptions,
    );

    enable(): void;

    disable(): void;

    finishDrag(): void;
}

export interface LayerOptions {
    pane?: string | undefined;
    attribution?: string | undefined;
}

export interface InteractiveLayerOptions extends LayerOptions {
    interactive?: boolean | undefined;
    bubblingMouseEvents?: boolean | undefined;
}

export class Layer extends Evented {
    constructor(options?: LayerOptions);
    addTo(map: Map | LayerGroup): this;
    remove(): this;
    removeFrom(map: Map): this;
    getPane(name?: string): HTMLElement | undefined;

    addInteractiveTarget(targetEl: HTMLElement): this;
    removeInteractiveTarget(targetEl: HTMLElement): this;

    // Popup methods
    bindPopup(content: ((layer: Layer) => Content) | Content | Popup, options?: PopupOptions): this;
    unbindPopup(): this;
    openPopup(latlng?: LatLngExpression): this;
    closePopup(): this;
    togglePopup(): this;
    isPopupOpen(): boolean;
    setPopupContent(content: Content | Popup): this;
    getPopup(): Popup | undefined;

    // Tooltip methods
    bindTooltip(content: ((layer: Layer) => Content) | Tooltip | Content, options?: TooltipOptions): this;
    unbindTooltip(): this;
    openTooltip(latlng?: LatLngExpression): this;
    closeTooltip(): this;
    toggleTooltip(): this;
    isTooltipOpen(): boolean;
    setTooltipContent(content: Content | Tooltip): this;
    getTooltip(): Tooltip | undefined;

    // Extension methods
    onAdd(map: Map): this;
    onRemove(map: Map): this;
    getEvents?(): { [name: string]: LeafletEventHandlerFn };
    getAttribution?(): string | null;
    beforeAdd?(map: Map): this;

    protected _map: Map;

    options: LayerOptions;
}

export interface GridLayerOptions extends LayerOptions {
    tileSize?: number | Point | undefined;
    opacity?: number | undefined;
    updateWhenIdle?: boolean | undefined;
    updateWhenZooming?: boolean | undefined;
    updateInterval?: number | undefined;
    zIndex?: number | undefined;
    bounds?: LatLngBoundsExpression | undefined;
    minZoom?: number | undefined;
    maxZoom?: number | undefined;
    /**
     * Maximum zoom number the tile source has available. If it is specified, the tiles on all zoom levels higher than
     * `maxNativeZoom` will be loaded from `maxNativeZoom` level and auto-scaled.
     */
    maxNativeZoom?: number | undefined;
    /**
     * Minimum zoom number the tile source has available. If it is specified, the tiles on all zoom levels lower than
     * `minNativeZoom` will be loaded from `minNativeZoom` level and auto-scaled.
     */
    minNativeZoom?: number | undefined;
    noWrap?: boolean | undefined;
    pane?: string | undefined;
    className?: string | undefined;
    keepBuffer?: number | undefined;
}

export type DoneCallback = (error?: Error, tile?: HTMLElement) => void;

export interface InternalTiles {
    [key: string]: {
        active?: boolean | undefined;
        coords: Coords;
        current: boolean;
        el: HTMLElement;
        loaded?: Date | undefined;
        retain?: boolean | undefined;
    };
}

export class GridLayer extends Layer {
    constructor(options?: GridLayerOptions);
    bringToFront(): this;
    bringToBack(): this;
    getContainer(): HTMLElement | null;
    setOpacity(opacity: number): this;
    setZIndex(zIndex: number): this;
    isLoading(): boolean;
    redraw(): this;
    getTileSize(): Point;

    protected createTile(coords: Coords, done: DoneCallback): HTMLElement;
    protected _tileCoordsToKey(coords: Coords): string;
    protected _wrapCoords(parameter: Coords): Coords;

    protected _tiles: InternalTiles;
    protected _tileZoom?: number | undefined;
}

export function gridLayer(options?: GridLayerOptions): GridLayer;

export interface TileLayerOptions extends GridLayerOptions {
    id?: string | undefined;
    accessToken?: string | undefined;
    minZoom?: number | undefined;
    maxZoom?: number | undefined;
    maxNativeZoom?: number | undefined;
    minNativeZoom?: number | undefined;
    subdomains?: string | string[] | undefined;
    errorTileUrl?: string | undefined;
    zoomOffset?: number | undefined;
    tms?: boolean | undefined;
    zoomReverse?: boolean | undefined;
    detectRetina?: boolean | undefined;
    crossOrigin?: CrossOrigin | boolean | undefined;
    referrerPolicy?: ReferrerPolicy | boolean | undefined;
    // [name: string]: any;
    // You are able add additional properties, but it makes this interface uncheckable.
    // See: https://github.com/DefinitelyTyped/DefinitelyTyped/issues/15313
    // Example:
    // tileLayer = L.tileLayer('http://{s}.tile.osm.org/{z}/{x}/{y}.png?{foo}&{bar}&{abc}', {foo: 'bar', bar: (data: any) => 'foo', abc: () => ''});
}

export class TileLayer extends GridLayer {
    constructor(urlTemplate: string, options?: TileLayerOptions);
    setUrl(url: string, noRedraw?: boolean): this;
    getTileUrl(coords: L.Coords): string;

    protected _tileOnLoad(done: L.DoneCallback, tile: HTMLElement): void;
    protected _tileOnError(done: L.DoneCallback, tile: HTMLElement, e: Error): void;
    protected _abortLoading(): void;
    protected _getZoomForUrl(): number;

    options: TileLayerOptions;
}

export function tileLayer(urlTemplate: string, options?: TileLayerOptions): TileLayer;

export namespace TileLayer {
    class WMS extends TileLayer {
        constructor(baseUrl: string, options: WMSOptions);
        setParams(params: WMSParams, noRedraw?: boolean): this;

        wmsParams: WMSParams;
        options: WMSOptions;
    }
}

export interface WMSOptions extends TileLayerOptions {
    layers?: string | undefined;
    styles?: string | undefined;
    format?: string | undefined;
    transparent?: boolean | undefined;
    version?: string | undefined;
    crs?: CRS | undefined;
    uppercase?: boolean | undefined;
}

export interface WMSParams {
    format?: string | undefined;
    layers: string;
    request?: string | undefined;
    service?: string | undefined;
    styles?: string | undefined;
    version?: string | undefined;
    transparent?: boolean | undefined;
    width?: number | undefined;
    height?: number | undefined;
}

export namespace tileLayer {
    function wms(baseUrl: string, options?: WMSOptions): TileLayer.WMS;
}

export type CrossOrigin = "anonymous" | "use-credentials" | "";
export type ReferrerPolicy =
    | "no-referrer"
    | "no-referrer-when-downgrade"
    | "origin"
    | "origin-when-cross-origin"
    | "same-origin"
    | "strict-origin"
    | "strict-origin-when-cross-origin"
    | "unsafe-url";

export interface ImageOverlayOptions extends InteractiveLayerOptions {
    opacity?: number | undefined;
    alt?: string | undefined;
    interactive?: boolean | undefined;
    crossOrigin?: CrossOrigin | boolean | undefined;
    errorOverlayUrl?: string | undefined;
    zIndex?: number | undefined;
    className?: string | undefined;
}

export interface ImageOverlayStyleOptions {
    opacity?: number;
    [name: string]: any;
}

export class ImageOverlay extends Layer {
    constructor(imageUrl: string, bounds: LatLngBoundsExpression, options?: ImageOverlayOptions);
    bringToFront(): this;
    bringToBack(): this;
    setUrl(url: string): this;

    /** Update the bounds that this ImageOverlay covers */
    setBounds(bounds: LatLngBounds): this;

    /** Changes the zIndex of the image overlay */
    setZIndex(value: number): this;

    /** Changes the opacity of the image element */
    setOpacity(opacity: number): this;

    /** Changes the style of the image element. As of 1.8, only the opacity is changed */
    setStyle(styleOpts: ImageOverlayStyleOptions): this;

    /** Get the bounds that this ImageOverlay covers */
    getBounds(): LatLngBounds;

    /** Get the center of the bounds this ImageOverlay covers */
    getCenter(): Point;

    /** Get the img element that represents the ImageOverlay on the map */
    getElement(): HTMLImageElement | undefined;

    options: ImageOverlayOptions;
}

export function imageOverlay(
    imageUrl: string,
    bounds: LatLngBoundsExpression,
    options?: ImageOverlayOptions,
): ImageOverlay;

export type SVGOverlayStyleOptions = ImageOverlayStyleOptions;

export class SVGOverlay extends Layer {
    /** SVGOverlay doesn't extend ImageOverlay because SVGOverlay.getElement returns SVGElement */

    constructor(svgImage: string | SVGElement, bounds: LatLngBoundsExpression, options?: ImageOverlayOptions);
    bringToFront(): this;
    bringToBack(): this;
    setUrl(url: string): this;

    /** Update the bounds that this SVGOverlay covers */
    setBounds(bounds: LatLngBounds): this;

    /** Changes the zIndex of the image overlay */
    setZIndex(value: number): this;

    /** Changes the opacity of the image element */
    setOpacity(opacity: number): this;

    /** Changes the style of the image element. As of 1.8, only the opacity is changed */
    setStyle(styleOpts: SVGOverlayStyleOptions): this;

    /** Get the bounds that this SVGOverlay covers */
    getBounds(): LatLngBounds;

    /** Get the center of the bounds this ImageOverlay covers */
    getCenter(): Point;

    /** Get the img element that represents the SVGOverlay on the map */
    getElement(): SVGElement | undefined;

    options: ImageOverlayOptions;
}

export function svgOverlay(
    svgImage: string | SVGElement,
    bounds: LatLngBoundsExpression,
    options?: ImageOverlayOptions,
): SVGOverlay;

export interface VideoOverlayOptions extends ImageOverlayOptions {
    /** Whether the video starts playing automatically when loaded. */
    autoplay?: boolean | undefined;
    /** Whether the video will loop back to the beginning when played. */
    loop?: boolean | undefined;
    /**
     * Whether the video will save aspect ratio after the projection. Relevant for supported browsers. See
     * [browser compatibility](https://developer.mozilla.org/en-US/docs/Web/CSS/object-fit)
     */
    keepAspectRatio?: boolean | undefined;
    /** Whether the video starts on mute when loaded. */
    muted?: boolean | undefined;
    playsInline?: boolean | undefined;
}

export class VideoOverlay extends Layer {
    /** VideoOverlay doesn't extend ImageOverlay because VideoOverlay.getElement returns HTMLImageElement */
    constructor(
        video: string | string[] | HTMLVideoElement,
        bounds: LatLngBoundsExpression,
        options?: VideoOverlayOptions,
    );
    bringToFront(): this;
    bringToBack(): this;
    setUrl(url: string): this;

    /** Update the bounds that this VideoOverlay covers */
    setBounds(bounds: LatLngBounds): this;

    /** Changes the zIndex of the image overlay */
    setZIndex(value: number): this;

    /** Changes the opacity of the image element */
    setOpacity(opacity: number): this;

    /** Changes the style of the image element. As of 1.8, only the opacity is changed */
    setStyle(styleOpts: SVGOverlayStyleOptions): this;

    /** Get the bounds that this VideoOverlay covers */
    getBounds(): LatLngBounds;

    /** Get the center of the bounds this ImageOverlay covers */
    getCenter(): Point;

    /** Get the video element that represents the VideoOverlay on the map */
    getElement(): HTMLVideoElement | undefined;

    options: VideoOverlayOptions;
}

export function videoOverlay(
    video: string | string[] | HTMLVideoElement,
    bounds: LatLngBoundsExpression,
    options?: VideoOverlayOptions,
): VideoOverlay;

export type LineCapShape = "butt" | "round" | "square" | "inherit";

export type LineJoinShape = "miter" | "round" | "bevel" | "inherit";

export type FillRule = "nonzero" | "evenodd" | "inherit";

export interface PathOptions extends InteractiveLayerOptions {
    stroke?: boolean | undefined;
    color?: string | undefined;
    weight?: number | undefined;
    opacity?: number | undefined;
    lineCap?: LineCapShape | undefined;
    lineJoin?: LineJoinShape | undefined;
    dashArray?: string | number[] | undefined;
    dashOffset?: string | undefined;
    fill?: boolean | undefined;
    fillColor?: string | undefined;
    fillOpacity?: number | undefined;
    fillRule?: FillRule | undefined;
    renderer?: Renderer | undefined;
    className?: string | undefined;
}

export abstract class Path extends Layer {
    redraw(): this;
    setStyle(style: PathOptions): this;
    bringToFront(): this;
    bringToBack(): this;
    getElement(): Element | undefined;

    options: PathOptions;
}

export interface PolylineOptions extends PathOptions {
    smoothFactor?: number | undefined;
    noClip?: boolean | undefined;
}

export class Polyline<T extends geojson.GeometryObject = geojson.LineString | geojson.MultiLineString, P = any>
    extends Path
{
    constructor(latlngs: LatLngExpression[] | LatLngExpression[][], options?: PolylineOptions);
    toGeoJSON(precision?: number | false): geojson.Feature<T, P>;
    getLatLngs(): LatLng[] | LatLng[][] | LatLng[][][];
    setLatLngs(latlngs: LatLngExpression[] | LatLngExpression[][] | LatLngExpression[][][]): this;
    isEmpty(): boolean;
    getCenter(): LatLng;
    getBounds(): LatLngBounds;
    addLatLng(latlng: LatLngExpression | LatLngExpression[], latlngs?: LatLng[]): this;
    closestLayerPoint(p: Point): Point;

    feature?: geojson.Feature<T, P> | undefined;
    options: PolylineOptions;
}

export function polyline<T extends geojson.GeometryObject = geojson.LineString | geojson.MultiLineString, P = any>(
    latlngs: LatLngExpression[] | LatLngExpression[][],
    options?: PolylineOptions,
): Polyline<T, P>;

export class Polygon<P = any> extends Polyline<geojson.Polygon | geojson.MultiPolygon, P> {
    constructor(latlngs: LatLngExpression[] | LatLngExpression[][] | LatLngExpression[][][], options?: PolylineOptions);
}

export function polygon<P = any>(
    latlngs: LatLngExpression[] | LatLngExpression[][] | LatLngExpression[][][],
    options?: PolylineOptions,
): Polygon<P>;

export class Rectangle<P = any> extends Polygon<P> {
    constructor(latLngBounds: LatLngBoundsExpression, options?: PolylineOptions);
    setBounds(latLngBounds: LatLngBoundsExpression): this;
}

export function rectangle<P = any>(latLngBounds: LatLngBoundsExpression, options?: PolylineOptions): Rectangle<P>;

export interface CircleMarkerOptions extends PathOptions {
    radius: number;
}

export class CircleMarker<P = any> extends Path {
    constructor(latlng: LatLngExpression, options: CircleMarkerOptions);
    toGeoJSON(precision?: number | false): geojson.Feature<geojson.Point, P>;
    setLatLng(latLng: LatLngExpression): this;
    getLatLng(): LatLng;
    setRadius(radius: number): this;
    getRadius(): number;
    setStyle(options: Partial<CircleMarkerOptions>): this;

    options: CircleMarkerOptions;
    feature?: geojson.Feature<geojson.Point, P> | undefined;
}

export function circleMarker<P = any>(latlng: LatLngExpression, options?: CircleMarkerOptions): CircleMarker<P>;

export type CircleOptions = CircleMarkerOptions;

export class Circle<P = any> extends CircleMarker<P> {
    constructor(latlng: LatLngExpression, options: CircleOptions);
    constructor(latlng: LatLngExpression, radius: number, options?: CircleOptions); // deprecated!
    toGeoJSON(precision?: number | false): any;
    getBounds(): LatLngBounds;
    setRadius(radius: number): this;
    getRadius(): number;
    setStyle(style: PathOptions): this;
}

export function circle<P = any>(latlng: LatLngExpression, options: CircleMarkerOptions): Circle<P>;
/**
 * @deprecated Passing the radius outside the options is deperecated. Use {@link circle:1} instead.
 */
export function circle<P = any>(latlng: LatLngExpression, radius: number, options?: CircleMarkerOptions): Circle<P>;

export interface RendererOptions extends LayerOptions {
    padding?: number | undefined;
    tolerance?: number | undefined;
}

export class Renderer extends Layer {
    constructor(options?: RendererOptions);

    options: RendererOptions;
}

export class SVG extends Renderer {}

export namespace SVG {
    function create<K extends keyof SVGElementTagNameMap>(name: K): SVGElementTagNameMap[K];
    function create(name: string): SVGElement;

    function pointsToPath(rings: PointExpression[], closed: boolean): string;
}

export function svg(options?: RendererOptions): SVG;

export class Canvas extends Renderer {}

export function canvas(options?: RendererOptions): Canvas;

/**
 * Used to group several layers and handle them as one.
 * If you add it to the map, any layers added or removed from the group will be
 * added/removed on the map as well. Extends Layer.
 */
export class LayerGroup<P = any> extends Layer {
    constructor(layers?: Layer[], options?: LayerOptions);

    toMultiPoint(precision?: number): geojson.Feature<geojson.MultiPoint, P>;

    /**
     * Returns a GeoJSON representation of the layer group (as a GeoJSON GeometryCollection, GeoJSONFeatureCollection or Multipoint).
     */
    toGeoJSON(
        precision?: number | false,
    ):
        | geojson.FeatureCollection<geojson.GeometryObject, P>
        | geojson.Feature<geojson.MultiPoint, P>
        | geojson.GeometryCollection;

    /**
     * Adds the given layer to the group.
     */
    addLayer(layer: Layer): this;

    /**
     * Removes the layer with the given internal ID or the given layer from the group.
     */
    removeLayer(layer: number | Layer): this;

    /**
     * Returns true if the given layer is currently added to the group.
     */
    hasLayer(layer: Layer): boolean;

    /**
     * Removes all the layers from the group.
     */
    clearLayers(): this;

    /**
     * Calls methodName on every layer contained in this group, passing any additional parameters.
     * Has no effect if the layers contained do not implement methodName.
     */
    invoke(methodName: string, ...params: any[]): this;

    /**
     * Iterates over the layers of the group,
     * optionally specifying context of the iterator function.
     */
    eachLayer(fn: (layer: Layer) => void, context?: any): this;

    /**
     * Returns the layer with the given internal ID.
     */
    getLayer(id: number): Layer | undefined;

    /**
     * Returns an array of all the layers added to the group.
     */
    getLayers(): Layer[];

    /**
     * Calls setZIndex on every layer contained in this group, passing the z-index.
     */
    setZIndex(zIndex: number): this;

    /**
     * Returns the internal ID for a layer
     */
    getLayerId(layer: Layer): number;

    feature?:
        | geojson.FeatureCollection<geojson.GeometryObject, P>
        | geojson.Feature<geojson.MultiPoint, P>
        | geojson.GeometryCollection
        | undefined;
}

/**
 * Create a layer group, optionally given an initial set of layers and an `options` object.
 */
export function layerGroup<P = any>(layers?: Layer[], options?: LayerOptions): LayerGroup<P>;

/**
 * Extended LayerGroup that also has mouse events (propagated from
 * members of the group) and a shared bindPopup method.
 */
export class FeatureGroup<P = any> extends LayerGroup<P> {
    /**
     * Adds the given layer to the group.
     */
    addLayer(layer: Layer): this;

    /**
     * Removes the layer with the given internal ID or the given layer from the group.
     */
    removeLayer(layer: number | Layer): this;

    /**
     * Sets the given path options to each layer of the group that has a setStyle method.
     */
    setStyle(style: PathOptions): this;

    /**
     * Brings the layer group to the top of all other layers
     */
    bringToFront(): this;

    /**
     * Brings the layer group to the top [sic] of all other layers
     */
    bringToBack(): this;

    /**
     * Returns the LatLngBounds of the Feature Group (created from
     * bounds and coordinates of its children).
     */
    getBounds(): LatLngBounds;
}

/**
 * Create a feature group, optionally given an initial set of layers.
 */
export function featureGroup<P = any>(layers?: Layer[], options?: LayerOptions): FeatureGroup<P>;

export type StyleFunction<P = any> = (feature?: geojson.Feature<geojson.GeometryObject, P>) => PathOptions;

export interface GeoJSONOptions<P = any, G extends geojson.GeometryObject = geojson.GeometryObject>
    extends InteractiveLayerOptions
{
    /**
     * A Function defining how GeoJSON points spawn Leaflet layers.
     * It is internally called when data is added, passing the GeoJSON point
     * feature and its LatLng.
     *
     * The default is to spawn a default Marker:
     *
     * ```
     * function(geoJsonPoint, latlng) {
     *     return L.marker(latlng);
     * }
     * ```
     */
    pointToLayer?(geoJsonPoint: geojson.Feature<geojson.Point, P>, latlng: LatLng): Layer; // should import GeoJSON typings

    /**
     * PathOptions or a Function defining the Path options for styling GeoJSON lines and polygons,
     * called internally when data is added.
     *
     * The default value is to not override any defaults:
     *
     * ```
     * function (geoJsonFeature) {
     *     return {}
     * }
     * ```
     */
    style?: PathOptions | StyleFunction<P> | undefined;

    /**
     * A Function that will be called once for each created Feature, after it
     * has been created and styled. Useful for attaching events and popups to features.
     *
     * The default is to do nothing with the newly created layers:
     *
     * ```
     * function (feature, layer) {}
     * ```
     */
    onEachFeature?(feature: geojson.Feature<G, P>, layer: Layer): void;

    /**
     * A Function that will be used to decide whether to show a feature or not.
     *
     * The default is to show all features:
     *
     * ```
     * function (geoJsonFeature) {
     *     return true;
     * }
     * ```
     */
    filter?(geoJsonFeature: geojson.Feature<G, P>): boolean;

    /**
     * A Function that will be used for converting GeoJSON coordinates to LatLngs.
     * The default is the coordsToLatLng static method.
     */
    coordsToLatLng?(coords: [number, number] | [number, number, number]): LatLng; // check if LatLng has an altitude property

    /** Whether default Markers for "Point" type Features inherit from group options. */
    markersInheritOptions?: boolean | undefined;
}

/**
 * Represents a GeoJSON object or an array of GeoJSON objects.
 * Allows you to parse GeoJSON data and display it on the map. Extends FeatureGroup.
 */
export class GeoJSON<P = any, G extends geojson.GeometryObject = geojson.GeometryObject> extends FeatureGroup<P> {
    /**
     * Convert layer into GeoJSON feature
     */
    static getFeature<P = any, G extends geojson.GeometryObject = geojson.GeometryObject>(
        layer: Layer,
        newGeometry: geojson.Feature<G, P> | G,
    ): geojson.Feature<G, P>;

    /**
     * Creates a Layer from a given GeoJSON feature. Can use a custom pointToLayer
     * and/or coordsToLatLng functions if provided as options.
     */
    static geometryToLayer<P = any, G extends geojson.GeometryObject = geojson.GeometryObject>(
        featureData: geojson.Feature<G, P>,
        options?: GeoJSONOptions<P, G>,
    ): Layer;

    /**
     * Creates a LatLng object from an array of 2 numbers (longitude, latitude) or
     * 3 numbers (longitude, latitude, altitude) used in GeoJSON for points.
     */
    static coordsToLatLng(coords: [number, number] | [number, number, number]): LatLng;

    /**
     * Creates a multidimensional array of LatLngs from a GeoJSON coordinates array.
     * levelsDeep specifies the nesting level (0 is for an array of points, 1 for an array of
     * arrays of points, etc., 0 by default).
     * Can use a custom coordsToLatLng function.
     */
    static coordsToLatLngs(
        coords: any[],
        levelsDeep?: number,
        coordsToLatLng?: (coords: [number, number] | [number, number, number]) => LatLng,
    ): any[]; // Using any[] to avoid artificially limiting valid calls

    /**
     * Reverse of coordsToLatLng
     */
    static latLngToCoords(latlng: LatLng): [number, number] | [number, number, number];

    /**
     * Reverse of coordsToLatLngs closed determines whether the first point should be
     * appended to the end of the array to close the feature, only used when levelsDeep is 0.
     * False by default.
     */
    static latLngsToCoords(latlngs: any[], levelsDeep?: number, closed?: boolean): any[]; // Using any[] to avoid artificially limiting valid calls

    /**
     * Normalize GeoJSON geometries/features into GeoJSON features.
     */
    static asFeature<P = any, G extends geojson.GeometryObject = geojson.GeometryObject>(
        geojson: geojson.Feature<G, P> | G,
    ): geojson.Feature<G, P>;

    constructor(geojson?: geojson.GeoJsonObject | null, options?: GeoJSONOptions<P, G> | null);
    /**
     * Adds a GeoJSON object to the layer.
     */
    addData(data: geojson.GeoJsonObject): this;

    /**
     * Resets the given vector layer's style to the original GeoJSON style,
     * useful for resetting style after hover events.
     */
    resetStyle(layer?: Layer): this;

    /**
     * Same as FeatureGroup's setStyle method, but style-functions are also
     * allowed here to set the style according to the feature.
     */
    setStyle(style: PathOptions | StyleFunction<P>): this;

    options: GeoJSONOptions<P, G>;
}

/**
 * Creates a GeoJSON layer.
 *
 * Optionally accepts an object in GeoJSON format to display on the
 * map (you can alternatively add it later with addData method) and
 * an options object.
 */
export function geoJSON<P = any, G extends geojson.GeometryObject = geojson.GeometryObject>(
    geojson?: geojson.GeoJsonObject | geojson.GeoJsonObject[] | null,
    options?: GeoJSONOptions<P, G> | null,
): GeoJSON<P, G>;
export function geoJson<P = any, G extends geojson.GeometryObject = geojson.GeometryObject>(
    geojson?: geojson.GeoJsonObject | geojson.GeoJsonObject[] | null,
    options?: GeoJSONOptions<P, G> | null,
): GeoJSON<P, G>;

export type Zoom = boolean | "center";

export interface MapOptions {
    preferCanvas?: boolean | undefined;

    // Control options
    attributionControl?: boolean | undefined;
    zoomControl?: boolean | undefined;

    // Interaction options
    closePopupOnClick?: boolean | undefined;
    zoomSnap?: number | undefined;
    zoomDelta?: number | undefined;
    trackResize?: boolean | undefined;
    boxZoom?: boolean | undefined;
    doubleClickZoom?: Zoom | undefined;
    dragging?: boolean | undefined;

    // Map state options
    crs?: CRS | undefined;
    center?: LatLngExpression | undefined;
    zoom?: number | undefined;
    minZoom?: number | undefined;
    maxZoom?: number | undefined;
    layers?: Layer[] | undefined;
    maxBounds?: LatLngBoundsExpression | undefined;
    renderer?: Renderer | undefined;

    // Animation options
    fadeAnimation?: boolean | undefined;
    markerZoomAnimation?: boolean | undefined;
    transform3DLimit?: number | undefined;
    zoomAnimation?: boolean | undefined;
    zoomAnimationThreshold?: number | undefined;

    // Panning inertia options
    inertia?: boolean | undefined;
    inertiaDeceleration?: number | undefined;
    inertiaMaxSpeed?: number | undefined;
    easeLinearity?: number | undefined;
    worldCopyJump?: boolean | undefined;
    maxBoundsViscosity?: number | undefined;

    // Keyboard navigation options
    keyboard?: boolean | undefined;
    keyboardPanDelta?: number | undefined;

    // Mousewheel options
    scrollWheelZoom?: Zoom | undefined;
    wheelDebounceTime?: number | undefined;
    wheelPxPerZoomLevel?: number | undefined;

    // Touch interaction options
    tap?: boolean | undefined;
    tapTolerance?: number | undefined;
    touchZoom?: Zoom | undefined;
    bounceAtZoomLimits?: boolean | undefined;
}

export type ControlPosition = "topleft" | "topright" | "bottomleft" | "bottomright";

export interface ControlOptions {
    position?: ControlPosition | undefined;
}

export class Control extends Class {
    static extend<T extends object>(props: T): { new(...args: any[]): T } & typeof Control;
    constructor(options?: ControlOptions);
    getPosition(): ControlPosition;
    setPosition(position: ControlPosition): this;
    getContainer(): HTMLElement | undefined;
    addTo(map: Map): this;
    remove(): this;

    // Extension methods
    onAdd?(map: Map): HTMLElement;
    onRemove?(map: Map): void;

    options: ControlOptions;
}

export namespace Control {
    interface ZoomOptions extends ControlOptions {
        zoomInText?: string | undefined;
        zoomInTitle?: string | undefined;
        zoomOutText?: string | undefined;
        zoomOutTitle?: string | undefined;
    }

    class Zoom extends Control {
        constructor(options?: ZoomOptions);
        options: ZoomOptions;
    }

    interface AttributionOptions extends ControlOptions {
        prefix?: string | boolean | undefined;
    }

    class Attribution extends Control {
        constructor(options?: AttributionOptions);
        setPrefix(prefix: string | false): this;
        addAttribution(text: string): this;
        removeAttribution(text: string): this;
        options: AttributionOptions;
    }

    interface LayersOptions extends ControlOptions {
        collapsed?: boolean | undefined;
        autoZIndex?: boolean | undefined;
        hideSingleBase?: boolean | undefined;
        /**
         * Whether to sort the layers. When `false`, layers will keep the order in which they were added to the control.
         */
        sortLayers?: boolean | undefined;
        /**
         * A [compare function](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Array/sort)
         * that will be used for sorting the layers, when `sortLayers` is `true`. The function receives both the
         * [`L.Layer`](https://leafletjs.com/reference.html#layer) instances and their names, as in
         * `sortFunction(layerA, layerB, nameA, nameB)`. By default, it sorts layers alphabetically by their name.
         */
        sortFunction?: ((layerA: Layer, layerB: Layer, nameA: string, nameB: string) => number) | undefined;
    }

    interface LayersObject {
        [name: string]: Layer;
    }

    class Layers extends Control {
        constructor(baseLayers?: LayersObject, overlays?: LayersObject, options?: LayersOptions);
        addBaseLayer(layer: Layer, name: string): this;
        addOverlay(layer: Layer, name: string): this;
        removeLayer(layer: Layer): this;
        expand(): this;
        collapse(): this;
        options: LayersOptions;
    }

    interface ScaleOptions extends ControlOptions {
        maxWidth?: number | undefined;
        metric?: boolean | undefined;
        imperial?: boolean | undefined;
        updateWhenIdle?: boolean | undefined;
    }

    class Scale extends Control {
        constructor(options?: ScaleOptions);
        options: ScaleOptions;
    }
}

export namespace control {
    function zoom(options?: Control.ZoomOptions): Control.Zoom;

    function attribution(options?: Control.AttributionOptions): Control.Attribution;

    function layers(
        baseLayers?: Control.LayersObject,
        overlays?: Control.LayersObject,
        options?: Control.LayersOptions,
    ): Control.Layers;

    function scale(options?: Control.ScaleOptions): Control.Scale;
}

export interface DivOverlayOptions {
    offset?: PointExpression | undefined;
    className?: string | undefined;
    pane?: string | undefined;
    interactive?: boolean | undefined;
    content?: string | HTMLElement | ((layer: Layer) => string) | ((layer: Layer) => HTMLElement);
}

export abstract class DivOverlay extends Layer {
    constructor(latlng: LatLngExpression, options?: TooltipOptions);
    constructor(options?: DivOverlayOptions, source?: Layer);
    getLatLng(): LatLng | undefined;
    setLatLng(latlng: LatLngExpression): this;
    getContent(): Content | ((source: Layer) => Content) | undefined;
    setContent(htmlContent: ((source: Layer) => Content) | Content): this;
    getElement(): HTMLElement | undefined;
    update(): void;
    isOpen(): boolean;
    bringToFront(): this;
    bringToBack(): this;
    openOn(map: Map): this;
    toggle(layer?: Layer): this;
    close(): this;

    options: DivOverlayOptions;
}

export interface PopupOptions extends DivOverlayOptions {
    maxWidth?: number | undefined;
    minWidth?: number | undefined;
    maxHeight?: number | undefined;
    keepInView?: boolean | undefined;
    closeButton?: boolean | undefined;
    autoPan?: boolean | undefined;
    autoPanPaddingTopLeft?: PointExpression | undefined;
    autoPanPaddingBottomRight?: PointExpression | undefined;
    autoPanPadding?: PointExpression | undefined;
    autoClose?: boolean | undefined;
    closeOnClick?: boolean | undefined;
    closeOnEscapeKey?: boolean | undefined;
}

export type Content = string | HTMLElement;

export class Popup extends DivOverlay {
    constructor(latlng: LatLngExpression, options?: TooltipOptions);
    constructor(options?: PopupOptions, source?: Layer);
    openOn(map: Map): this;

    options: PopupOptions;
}

export function popup(options?: PopupOptions, source?: Layer): Popup;

export type Direction = "right" | "left" | "top" | "bottom" | "center" | "auto";

export interface TooltipOptions extends DivOverlayOptions {
    pane?: string | undefined;
    offset?: PointExpression | undefined;
    direction?: Direction | undefined;
    permanent?: boolean | undefined;
    sticky?: boolean | undefined;
    opacity?: number | undefined;
}

export class Tooltip extends DivOverlay {
    constructor(latlng: LatLngExpression, options?: TooltipOptions);
    constructor(options?: TooltipOptions, source?: Layer);
    setOpacity(val: number): void;

    options: TooltipOptions;
}

export function tooltip(options?: TooltipOptions, source?: Layer): Tooltip;

export interface ZoomOptions {
    animate?: boolean | undefined;
}

export interface PanOptions {
    animate?: boolean | undefined;
    duration?: number | undefined;
    easeLinearity?: number | undefined;
    noMoveStart?: boolean | undefined;
}

// This is not empty, it extends two interfaces into one...
export interface ZoomPanOptions extends ZoomOptions, PanOptions {}

export interface InvalidateSizeOptions extends ZoomPanOptions {
    debounceMoveend?: boolean | undefined;
    pan?: boolean | undefined;
}

export interface FitBoundsOptions extends ZoomOptions, PanOptions {
    paddingTopLeft?: PointExpression | undefined;
    paddingBottomRight?: PointExpression | undefined;
    padding?: PointExpression | undefined;
    maxZoom?: number | undefined;
}

export interface PanInsideOptions extends PanOptions {
    paddingTopLeft?: PointExpression | undefined;
    paddingBottomRight?: PointExpression | undefined;
    padding?: PointExpression | undefined;
}

export interface LocateOptions {
    watch?: boolean | undefined;
    setView?: boolean | undefined;
    maxZoom?: number | undefined;
    timeout?: number | undefined;
    maximumAge?: number | undefined;
    enableHighAccuracy?: boolean | undefined;
}

export class Handler extends Class {
    constructor(map: Map);
    enable(): this;
    disable(): this;
    enabled(): boolean;

    // Extension methods
    addHooks?(): void;
    removeHooks?(): void;
}

export interface LeafletEvent {
    type: string;
    popup: any;
    target: any;
    sourceTarget: any;
    propagatedFrom: any;
    /**
     * @deprecated The same as {@link LeafletEvent.propagatedFrom propagatedFrom}.
     */
    layer: any;
}

export interface LeafletMouseEvent extends LeafletEvent {
    latlng: LatLng;
    layerPoint: Point;
    containerPoint: Point;
    originalEvent: MouseEvent;
}

export interface LeafletKeyboardEvent extends LeafletEvent {
    originalEvent: KeyboardEvent;
}

export interface LocationEvent extends LeafletEvent {
    latlng: LatLng;
    bounds: LatLngBounds;
    accuracy: number;
    altitude: number;
    altitudeAccuracy: number;
    heading: number;
    speed: number;
    timestamp: number;
}

export interface ErrorEvent extends LeafletEvent {
    message: string;
    code: number;
}

export interface LayerEvent extends LeafletEvent {
    layer: Layer;
}

export interface LayersControlEvent extends LayerEvent {
    name: string;
}

export interface TileEvent extends LeafletEvent {
    tile: HTMLImageElement;
    coords: Coords;
}

export interface TileErrorEvent extends TileEvent {
    error: Error;
}

export interface ResizeEvent extends LeafletEvent {
    oldSize: Point;
    newSize: Point;
}

export interface GeoJSONEvent extends LeafletEvent {
    layer: Layer;
    properties: any;
    geometryType: string;
    id: string;
}

export interface PopupEvent extends LeafletEvent {
    popup: Popup;
}

export interface TooltipEvent extends LeafletEvent {
    tooltip: Tooltip;
}

export interface DragEndEvent extends LeafletEvent {
    distance: number;
}

export interface ZoomAnimEvent extends LeafletEvent {
    center: LatLng;
    zoom: number;
    noUpdate: boolean;
}

export namespace DomEvent {
    type EventHandlerFn = (event: Event) => void;

    type PropagableEvent = LeafletMouseEvent | LeafletKeyboardEvent | LeafletEvent | Event;

    function on(el: HTMLElement, types: string, fn: EventHandlerFn, context?: any): typeof DomEvent;

    function on(el: HTMLElement, eventMap: { [eventName: string]: EventHandlerFn }, context?: any): typeof DomEvent;

    // tslint:disable:unified-signatures
    function off(el: HTMLElement): typeof DomEvent;

    function off(el: HTMLElement, types: string, fn: EventHandlerFn, context?: any): typeof DomEvent;

    function off(el: HTMLElement, eventMap: { [eventName: string]: EventHandlerFn }, context?: any): typeof DomEvent;
    // tslint:enable:unified-signatures

    function stopPropagation(ev: PropagableEvent): typeof DomEvent;

    function disableScrollPropagation(el: HTMLElement): typeof DomEvent;

    function disableClickPropagation(el: HTMLElement): typeof DomEvent;

    function preventDefault(ev: Event): typeof DomEvent;

    function stop(ev: PropagableEvent): typeof DomEvent;

    function getMousePosition(ev: MouseEvent, container?: HTMLElement): Point;

    function getWheelDelta(ev: Event): number;

    function addListener(el: HTMLElement, types: string, fn: EventHandlerFn, context?: any): typeof DomEvent;

    function addListener(
        el: HTMLElement,
        eventMap: { [eventName: string]: EventHandlerFn },
        context?: any,
    ): typeof DomEvent;

    function removeListener(el: HTMLElement, types: string, fn: EventHandlerFn, context?: any): typeof DomEvent;

    function removeListener(
        el: HTMLElement,
        eventMap: { [eventName: string]: EventHandlerFn },
        context?: any,
    ): typeof DomEvent;

    function getPropagationPath(ev: Event): HTMLElement[];
}

export interface DefaultMapPanes {
    mapPane: HTMLElement;
    tilePane: HTMLElement;
    overlayPane: HTMLElement;
    shadowPane: HTMLElement;
    markerPane: HTMLElement;
    tooltipPane: HTMLElement;
    popupPane: HTMLElement;
}

export class Map extends Evented {
    constructor(element: string | HTMLElement, options?: MapOptions);
    getRenderer(layer: Path): Renderer;

    // Methods for layers and controls
    addControl(control: Control): this;
    removeControl(control: Control): this;
    addLayer(layer: Layer): this;
    removeLayer(layer: Layer): this;
    hasLayer(layer: Layer): boolean;
    eachLayer(fn: (layer: Layer) => void, context?: any): this;
    openPopup(popup: Popup): this;
    openPopup(content: Content, latlng: LatLngExpression, options?: PopupOptions): this;
    closePopup(popup?: Popup): this;
    openTooltip(tooltip: Tooltip): this;
    openTooltip(content: Content, latlng: LatLngExpression, options?: TooltipOptions): this;
    closeTooltip(tooltip?: Tooltip): this;

    // Methods for modifying map state
    setView(center: LatLngExpression, zoom?: number, options?: ZoomPanOptions): this;
    setZoom(zoom: number, options?: ZoomPanOptions): this;
    zoomIn(delta?: number, options?: ZoomOptions): this;
    zoomOut(delta?: number, options?: ZoomOptions): this;
    setZoomAround(position: Point | LatLngExpression, zoom: number, options?: ZoomOptions): this;
    fitBounds(bounds: LatLngBoundsExpression, options?: FitBoundsOptions): this;
    fitWorld(options?: FitBoundsOptions): this;
    panTo(latlng: LatLngExpression, options?: PanOptions): this;
    panBy(offset: PointExpression, options?: PanOptions): this;
    setMaxBounds(bounds: LatLngBoundsExpression): this;
    setMinZoom(zoom: number): this;
    setMaxZoom(zoom: number): this;
    panInside(latLng: LatLngExpression, options?: PanInsideOptions): this;
    panInsideBounds(bounds: LatLngBoundsExpression, options?: PanOptions): this;
    /**
     * Boolean for animate or advanced ZoomPanOptions
     */
    invalidateSize(options?: boolean | InvalidateSizeOptions): this;
    stop(): this;
    flyTo(latlng: LatLngExpression, zoom?: number, options?: ZoomPanOptions): this;
    flyToBounds(bounds: LatLngBoundsExpression, options?: FitBoundsOptions): this;

    // Other methods
    addHandler(name: string, HandlerClass: typeof Handler): this; // Alternatively, HandlerClass: new(map: Map) => Handler
    remove(): this;
    createPane(name: string, container?: HTMLElement): HTMLElement;
    /**
     * Name of the pane or the pane as HTML-Element
     */
    getPane(pane: string | HTMLElement): HTMLElement | undefined;
    getPanes(): { [name: string]: HTMLElement } & DefaultMapPanes;
    getContainer(): HTMLElement;
    whenReady(fn: () => void, context?: any): this;

    // Methods for getting map state
    getCenter(): LatLng;
    getZoom(): number;
    getBounds(): LatLngBounds;
    getMinZoom(): number;
    getMaxZoom(): number;
    getBoundsZoom(bounds: LatLngBoundsExpression, inside?: boolean, padding?: Point): number;
    getSize(): Point;
    getPixelBounds(): Bounds;
    getPixelOrigin(): Point;
    getPixelWorldBounds(zoom?: number): Bounds;

    // Conversion methods
    getZoomScale(toZoom: number, fromZoom?: number): number;
    getScaleZoom(scale: number, fromZoom?: number): number;
    project(latlng: LatLngExpression, zoom?: number): Point;
    unproject(point: PointExpression, zoom?: number): LatLng;
    layerPointToLatLng(point: PointExpression): LatLng;
    latLngToLayerPoint(latlng: LatLngExpression): Point;
    wrapLatLng(latlng: LatLngExpression): LatLng;
    wrapLatLngBounds(bounds: LatLngBounds): LatLngBounds;
    distance(latlng1: LatLngExpression, latlng2: LatLngExpression): number;
    containerPointToLayerPoint(point: PointExpression): Point;
    containerPointToLatLng(point: PointExpression): LatLng;
    layerPointToContainerPoint(point: PointExpression): Point;
    latLngToContainerPoint(latlng: LatLngExpression): Point;
    mouseEventToContainerPoint(ev: MouseEvent): Point;
    mouseEventToLayerPoint(ev: MouseEvent): Point;
    mouseEventToLatLng(ev: MouseEvent): LatLng;

    // Geolocation methods
    locate(options?: LocateOptions): this;
    stopLocate(): this;

    // Properties
    attributionControl: L.Control.Attribution;
    boxZoom: Handler;
    doubleClickZoom: Handler;
    dragging: Handler;
    keyboard: Handler;
    scrollWheelZoom: Handler;
    tap?: Handler | undefined;
    touchZoom: Handler;
    zoomControl: Control.Zoom;

    options: MapOptions;
}

/**
 * ID of a HTML-Element as string or the HTML-ELement itself
 */
export function map(element: string | HTMLElement, options?: MapOptions): Map;

export interface BaseIconOptions extends LayerOptions {
    iconUrl?: string | undefined;
    iconRetinaUrl?: string | undefined;
    iconSize?: PointExpression | undefined;
    iconAnchor?: PointExpression | undefined;
    popupAnchor?: PointExpression | undefined;
    tooltipAnchor?: PointExpression | undefined;
    shadowUrl?: string | undefined;
    shadowRetinaUrl?: string | undefined;
    shadowSize?: PointExpression | undefined;
    shadowAnchor?: PointExpression | undefined;
    className?: string | undefined;
}

export interface IconOptions extends BaseIconOptions {
    iconUrl: string;
    crossOrigin?: CrossOrigin | boolean | undefined;
}

export class Icon<T extends BaseIconOptions = IconOptions> extends Layer {
    constructor(options: T);
    createIcon(oldIcon?: HTMLElement): HTMLElement;
    createShadow(oldIcon?: HTMLElement): HTMLElement;

    options: T;
}

export namespace Icon {
    interface DefaultIconOptions extends BaseIconOptions {
        imagePath?: string | undefined;
    }

    class Default extends Icon<DefaultIconOptions> {
        static imagePath?: string | undefined;
        constructor(options?: DefaultIconOptions);
    }
}

export function icon(options: IconOptions): Icon;

export interface DivIconOptions extends BaseIconOptions {
    html?: string | HTMLElement | false | undefined;
    bgPos?: PointExpression | undefined;
    iconSize?: PointExpression | undefined;
    iconAnchor?: PointExpression | undefined;
    popupAnchor?: PointExpression | undefined;
    className?: string | undefined;
}

export class DivIcon extends Icon<DivIconOptions> {
    constructor(options?: DivIconOptions);
}

export function divIcon(options?: DivIconOptions): DivIcon;

export interface MarkerOptions extends InteractiveLayerOptions {
    icon?: Icon | DivIcon | undefined;
    /** Whether the marker is draggable with mouse/touch or not. */
    draggable?: boolean | undefined;
    /** Whether the marker can be tabbed to with a keyboard and clicked by pressing enter. */
    keyboard?: boolean | undefined;
    /** Text for the browser tooltip that appear on marker hover (no tooltip by default). */
    title?: string | undefined;
    /** Text for the `alt` attribute of the icon image (useful for accessibility). */
    alt?: string | undefined;
    /** Option for putting the marker on top of all others (or below). */
    zIndexOffset?: number | undefined;
    /** The opacity of the marker. */
    opacity?: number | undefined;
    /** If `true`, the marker will get on top of others when you hover the mouse over it. */
    riseOnHover?: boolean | undefined;
    /** The z-index offset used for the `riseOnHover` feature. */
    riseOffset?: number | undefined;
    /** `Map pane` where the markers shadow will be added. */
    shadowPane?: string | undefined;
    /** Whether to pan the map when dragging this marker near its edge or not. */
    autoPan?: boolean | undefined;
    /** Distance (in pixels to the left/right and to the top/bottom) of the map edge to start panning the map. */
    autoPanPadding?: PointExpression | undefined;
    /** Number of pixels the map should pan by. */
    autoPanSpeed?: number | undefined;
    autoPanOnFocus?: boolean | undefined;
}

export class Marker<P = any> extends Layer {
    constructor(latlng: LatLngExpression, options?: MarkerOptions);
    toGeoJSON(precision?: number | false): geojson.Feature<geojson.Point, P>;
    getLatLng(): LatLng;
    setLatLng(latlng: LatLngExpression): this;
    setZIndexOffset(offset: number): this;
    getIcon(): Icon | DivIcon;
    setIcon(icon: Icon | DivIcon): this;
    setOpacity(opacity: number): this;
    getElement(): HTMLElement | undefined;

    // Properties
    options: MarkerOptions;
    dragging?: Handler | undefined;
    feature?: geojson.Feature<geojson.Point, P> | undefined;

    protected _shadow: HTMLElement | undefined;
}

export function marker<P = any>(latlng: LatLngExpression, options?: MarkerOptions): Marker<P>;

export namespace Browser {
    // sorting according to https://leafletjs.com/reference-1.5.0.html#browser
    const ie: boolean;
    const ielt9: boolean;
    const edge: boolean;
    const webkit: boolean;
    const android: boolean;
    const android23: boolean;
    const androidStock: boolean;
    const opera: boolean;
    const chrome: boolean;
    const gecko: boolean;
    const safari: boolean;
    const opera12: boolean;
    const win: boolean;
    const ie3d: boolean;
    const webkit3d: boolean;
    const gecko3d: boolean;
    const any3d: boolean;
    const mobile: boolean;
    const mobileWebkit: boolean;
    const mobileWebkit3d: boolean;
    const msPointer: boolean;
    const pointer: boolean;
    const touch: boolean;
    const mobileOpera: boolean;
    const mobileGecko: boolean;
    const retina: boolean;
    const canvas: boolean;
    const svg: boolean;
    const vml: boolean;
}

export namespace Util {
    function extend<D extends object, S1 extends object = {}>(dest: D, src?: S1): D & S1;
    function extend<D extends object, S1 extends object, S2 extends object>(dest: D, src1: S1, src2: S2): D & S1 & S2;
    function extend<D extends object, S1 extends object, S2 extends object, S3 extends object>(
        dest: D,
        src1: S1,
        src2: S2,
        src3: S3,
    ): D & S1 & S2 & S3;
    function extend(dest: any, ...src: any[]): any;

    function create(proto: object | null, properties?: PropertyDescriptorMap): any;
    function bind(fn: (...args: any[]) => void, ...obj: any[]): () => void;
    function stamp(obj: any): number;
    function throttle(fn: () => void, time: number, context: any): () => void;
    function wrapNum(num: number, range: number[], includeMax?: boolean): number;
    function falseFn(): false;
    function formatNum(num: number, digits?: number | false): number;
    function trim(str: string): string;
    function splitWords(str: string): string[];
    function setOptions(obj: any, options: any): any;
    function getParamString(obj: any, existingUrl?: string, uppercase?: boolean): string;
    function template(str: string, data: any): string;
    function isArray(obj: any): boolean;
    function indexOf(array: any[], el: any): number;
    function requestAnimFrame(fn: (timestamp: number) => void, context?: any, immediate?: boolean): number;
    function cancelAnimFrame(id: number): void;

    let lastId: number;
    let emptyImageUrl: string;
}

export const extend: typeof Util["extend"];
export const bind: typeof Util["bind"];
export const stamp: typeof Util["stamp"];
export const setOptions: typeof Util["setOptions"];

export function noConflict(): any;


/**********************************************************/
/*                                                        */
/*             custom element auxilary types              */
/*                                                        */
/**********************************************************/
type MapAttributes = {
    hasLocation: boolean;
    streetNumber: string;
    street: string;
    city: string;
    state: string;
    zip: string;
    lat: number;
    long: number;
}

type CalendarAttributes = {
    year: number;
    month: number;
    day: number;
    hour: number;
    minute: number;
    activeYear: number;
    activeMonth: number;
    hourTemp: string;
    minuteTemp: string;
}

type Option = {
    value: string;
    label: string;
}

/**********************************************************/
/*                                                        */
/*                  custom element types                  */
/*                                                        */
/**********************************************************/
type FormFieldBaseAttributes = {
    id: string;
    type: string;
    name: string;
    label?: string;
    includeLabel: boolean;
    description?: string;
    layout: string;
    required: boolean;
    readonly: boolean;
    disabled: boolean;
    hidden: boolean;
};

type TextFormFieldAttributes = FormFieldBaseAttributes & {
    placeholder?: string?;
    defaultValue?: string;
    max: number;
    min: number;
};

type NumberInputAttributes = FormFieldBaseAttributes & {
    placeholder: string;
    defaultValue?: string;
    max: number;
    min: number;
    step: number;
    decimals: number;
};

type SelectFormFieldAttributes = FormFieldBaseAttributes & {
    prompt: string;
    defaultValue?: string;
    options: Option[];
    multiselect: boolean;
    columns: number;
    dropdown: boolean;
};

type LocationFormFieldAttributes = FormFieldBaseAttributes & {
    placeholder: string;
    address: string;
    streetNumber: string;
    street: string;
    city: string;
    state: string;
    zip: string;
    lat: number;
    long: number;
    defaultCurrent: boolean;
}

type CalculationFormFieldAttributes = FormFieldBaseAttributes & {
    calculationType: string;
    calculation: string;
    fields: string[];
}

type DateTimeFormFieldAttributes = FormFieldBaseAttributes & {
    placeholder: string;
    defaultValue?: string;
    max: number;
    min: number;
    includeDate: boolean,
    incudeTime: boolean,
}

type HeadingFormFieldAttributes = FormFieldBaseAttributes & {
    heading: string;
    align: "left" | "center" | "right";
    color: string;
}

type ParagraphFormFieldAttributes = FormFieldBaseAttributes & {
    text: string;
    align: "left" | "center" | "right";
    color: string;
}

type HtmlFormFieldAttributes = FormFieldBaseAttributes & {
    html: string;
}

type ListComponentAttributes = FormFieldBaseAttributes & {
    includeColumnHeaders: boolean;
    columns: string[];
    fields: string[];
    listItems: string[];
}

type FormFieldAttributes = 
    TextFormFieldAttributes | 
    NumberInputAttributes | 
    SelectFormFieldAttributes | 
    LocationFormFieldAttributes |
    CalculationFormFieldAttributes |
    DateTimeFormFieldAttributes |
    HeadingFormFieldAttributes | 
    ParagraphFormFieldAttributes | 
    HtmlFormFieldAttributes;
