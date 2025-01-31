// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

export class Rest {
  private static instance: Rest;

  private constructor() {}

  public static getInstance() {
    if (!Rest.instance) {
      Rest.instance = new Rest();
    }

    return Rest.instance;
  }
}

export const RestInhabitant: Rest = Rest.getInstance();

export function isRest(v: any): v is Rest {
  return v instanceof Rest && v === RestInhabitant;
}
