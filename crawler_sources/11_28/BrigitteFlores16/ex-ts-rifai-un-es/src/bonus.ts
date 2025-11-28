//Bonus
//Scegli un esercizio tra Carrello della Spesa, Lista di Politici, Autocomplete e Web Developer Signup del Modulo 2 – Advanced React e riscrivilo in React + TypeScript.
//Tipizza:
//le props dei componenti
//eventuali hook (useState, useReducer, useRef, useContext)
//Avvia il progetto e verifica che tutte le tipizzazioni siano corrette.

// esercizio carello della spesa

interface Product {
  name: string;
  price: number;
}

interface CartItem extends Product {
  quantity: number;
}

type CartAction =
  | { type: "ADD_ITEM"; payload: Product }
  | { type: "REMOVE_ITEM"; payload: string }
  | { type: "UPDATE_QUANTITY"; payload: { name: string; quantity: number } };

const products: Product[] = [
  { name: "Mela", price: 0.5 },
  { name: "Pane", price: 1.2 },
  { name: "Latte", price: 1.0 },
  { name: "Pasta", price: 0.7 },
];

class ShoppingCart {
  private cart: CartItem[] = [];

  constructor() {
    this.initializeUI();
  }

  private cartReducer(state: CartItem[], action: CartAction): CartItem[] {
    switch (action.type) {
      case "ADD_ITEM":
        const existingProduct = state.find((p) => p.name === action.payload.name);
        if (existingProduct) {
          return state.map((p) =>
            p.name === action.payload.name
              ? { ...p, quantity: p.quantity + 1 }
              : p
          );
        }
        return [...state, { ...action.payload, quantity: 1 }];

      case "REMOVE_ITEM":
        return state.filter((product) => product.name !== action.payload);

      case "UPDATE_QUANTITY":
        return state.map((product) =>
          product.name === action.payload.name
            ? {
                ...product,
                quantity: Math.max(1, Math.floor(Number(action.payload.quantity))),
              }
            : product
        );

      default:
        return state;
    }
  }

  private dispatch(action: CartAction): void {
    this.cart = this.cartReducer(this.cart, action);
    this.updateCartUI();
  }

  private createProductList(): void {
    const productList = document.createElement('div');
    productList.innerHTML = `
      <h2>Lista Prodotti</h2>
      <ul>
        ${products.map(product => `
          <li>
            <strong>${product.name}</strong>: €${product.price.toFixed(2)}
            <button class="add-to-cart" data-product='${JSON.stringify(product)}'>
              Aggiungi al carrello
            </button>
          </li>
        `).join('')}
      </ul>
    `;

    productList.addEventListener('click', (e: Event) => {
      const target = e.target as HTMLElement;
      if (target.classList.contains('add-to-cart')) {
        const product: Product = JSON.parse(target.getAttribute('data-product') || '{}');
        this.dispatch({ type: "ADD_ITEM", payload: product });
      }
    });

    document.body.appendChild(productList);
  }

  private updateCartUI(): void {
    let cartContainer = document.getElementById('cart-container');
    if (!cartContainer) {
      cartContainer = document.createElement('div');
      cartContainer.id = 'cart-container';
      document.body.appendChild(cartContainer);
    }

    if (this.cart.length === 0) {
      cartContainer.innerHTML = '';
      return;
    }

    cartContainer.innerHTML = `
      <h3>Carrello</h3>
      <ul>
        ${this.cart.map(item => `
          <li>
            <strong>${item.name}</strong>: €${item.price.toFixed(2)}
            <input type="number" 
                   value="${item.quantity}" 
                   min="1" 
                   class="quantity-input"
                   data-product="${item.name}"
            >
            <button class="remove-item" data-product="${item.name}">
              Rimuovi
            </button>
          </li>
        `).join('')}
      </ul>
      <h3>Totale: €${this.calculateTotal().toFixed(2)}</h3>
    `;

    cartContainer.querySelectorAll('.quantity-input').forEach((input: Element) => {
      input.addEventListener('change', (e: Event) => {
        const target = e.target as HTMLInputElement;
        const name = target.getAttribute('data-product') || '';
        this.dispatch({
          type: "UPDATE_QUANTITY",
          payload: { name, quantity: parseInt(target.value, 10) }
        });
      });
    });

    cartContainer.querySelectorAll('.remove-item').forEach((button: Element) => {
      button.addEventListener('click', (e: Event) => {
        const target = e.target as HTMLElement;
        const name = target.getAttribute('data-product') || '';
        this.dispatch({ type: "REMOVE_ITEM", payload: name });
      });
    });
  }

  private calculateTotal(): number {
    return this.cart.reduce((total, item) => total + item.price * item.quantity, 0);
  }

  private initializeUI(): void {
    this.createProductList();
    this.updateCartUI();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  new ShoppingCart();
});
